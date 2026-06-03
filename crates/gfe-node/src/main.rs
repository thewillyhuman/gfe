//! `gfe-node` — the main GFE binary: runs the proxy (data plane) and the
//! control-plane pieces (config load/apply, ops server) on one box.

mod ops;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use clap::Parser;
use gfe_controller::Controller;
use gfe_metrics::GfeMetrics;
use gfe_proxy::{DrainController, ProxyEngine, ProxyShared};
use gfe_router::RouteTable;
use gfe_tls::{CertStore, ChallengeStore, SniResolver};
use gfe_upstream::{HealthMap, PoolSet, UpstreamClient, UpstreamClientOptions};
use ops::OpsState;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "gfe-node",
    version,
    about = "General Front End — L7 TLS proxy node"
)]
struct Args {
    /// Path to the bootstrap node config (TOML).
    #[arg(long)]
    config: PathBuf,
    /// Validate the bootstrap and dynamic config, then exit.
    #[arg(long)]
    check_config: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Load and validate config before doing anything else.
    let node = gfe_config::load_node_config(&args.config)
        .with_context(|| format!("loading node config {}", args.config.display()))?;
    let dynamic =
        gfe_config::load_dynamic_config(&node.control_plane.config_file).with_context(|| {
            format!(
                "loading dynamic config {}",
                node.control_plane.config_file.display()
            )
        })?;
    gfe_config::validate(&dynamic).context("validating dynamic config")?;

    if args.check_config {
        println!(
            "config OK: {} listeners, {} routes, {} pools, {} certificates",
            dynamic.listeners.len(),
            dynamic.routes.len(),
            dynamic.pools.len(),
            dynamic.certificates.len()
        );
        return Ok(());
    }

    init_tracing();

    let mut rt = tokio::runtime::Builder::new_multi_thread();
    rt.enable_all();
    if node.node.worker_threads > 0 {
        rt.worker_threads(node.node.worker_threads);
    }
    let rt = rt.build().context("building tokio runtime")?;
    rt.block_on(run(node))
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(false)
        .init();
}

async fn run(node: gfe_types::NodeConfig) -> Result<()> {
    tracing::info!(node = %node.node.id, vip = %node.node.loopback_vip, "starting gfe-node");

    let metrics = Arc::new(GfeMetrics::new());

    // Build the shared data-plane state with empty snapshots.
    let resolver = Arc::new(SniResolver::new(CertStore::default()));
    let shared = Arc::new(ProxyShared {
        routes: ArcSwap::from_pointee(RouteTable::default()),
        pools: ArcSwap::from_pointee(PoolSet::default()),
        resolver: resolver.clone(),
        challenges: Arc::new(ChallengeStore::new()),
        health: Arc::new(HealthMap::new(true)),
        upstream: build_upstream_client(&node.upstream)?,
        metrics: metrics.clone(),
        limits: node.limits.clone(),
        timeouts: node.timeouts.clone(),
        tls: node.tls.clone(),
        draining: AtomicBool::new(false),
    });

    // Start the control plane: initial config load/apply (with cache
    // fallback), health probes, last-known-good cache, and hot-reload watcher.
    let mut controller = Controller::new(shared.clone(), &node);
    let dynamic = controller
        .start()
        .map_err(|e| anyhow::anyhow!("starting controller: {e}"))?;

    // Build the TLS server config (shared across https listeners). Cert
    // rotation flows through the resolver's swappable store, so this need not
    // be rebuilt on reload.
    let server_config = Arc::new(
        gfe_tls::server_config(resolver.clone(), node.tls.min_version)
            .map_err(|e| anyhow::anyhow!("building TLS server config: {e}"))?,
    );

    // Readiness + drain plumbing. The ops server reads `draining` from the
    // shared state; the engine watches the drain controller's channel.
    let ready = Arc::new(AtomicBool::new(false));
    let drain = DrainController::new();
    let engine_rx = drain.subscribe();

    // Ops server.
    let ops_state = Arc::new(OpsState {
        metrics: metrics.clone(),
        ready: ready.clone(),
        shared: shared.clone(),
    });
    {
        let addr = node.node.metrics_addr;
        let st = ops_state.clone();
        tokio::spawn(async move {
            if let Err(e) = ops::run(addr, st).await {
                tracing::error!(error = %e, "ops server failed");
            }
        });
    }

    // Bind listeners up front (fail fast), then mark ready and serve.
    let bound = ProxyEngine::bind(&dynamic.listeners)
        .await
        .context("binding listeners")?;
    let engine = ProxyEngine::new(shared.clone());

    // Signal handling → drain.
    {
        let drain_shared = shared.clone();
        tokio::spawn(async move {
            wait_for_shutdown().await;
            tracing::info!("shutdown signal received, draining");
            drain.trigger(&drain_shared);
        });
    }

    ready.store(true, Ordering::SeqCst);
    tracing::info!(listeners = bound.len(), "gfe-node ready");

    engine.serve(bound, server_config, engine_rx).await;

    controller.shutdown();
    tracing::info!("gfe-node stopped");
    Ok(())
}

/// Build the upstream client from the node's `[upstream]` config (idle pool
/// size, optional extra CA bundle, optional mTLS client certificate).
fn build_upstream_client(cfg: &gfe_types::UpstreamConfig) -> Result<UpstreamClient> {
    fn read(p: &Path) -> Result<Vec<u8>> {
        std::fs::read(p).with_context(|| format!("reading {}", p.display()))
    }
    let opts = UpstreamClientOptions {
        idle_per_host: cfg.idle_per_host.unwrap_or(32),
        client_cert_pem: cfg.client_cert_file.as_deref().map(read).transpose()?,
        client_key_pem: cfg.client_key_file.as_deref().map(read).transpose()?,
        extra_ca_pem: cfg.extra_ca_file.as_deref().map(read).transpose()?,
    };
    UpstreamClient::with_options(opts).map_err(|e| anyhow::anyhow!("building upstream client: {e}"))
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
