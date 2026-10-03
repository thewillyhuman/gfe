//! `gfe-node` — the main GFE binary: runs the proxy (data plane) and the
//! control-plane pieces (config load/apply, ops server) on one box.

mod ops;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use clap::Parser;
use gfe_controller::Controller;
use gfe_metrics::GfeMetrics;
use gfe_proxy::{DrainController, ListenerSet, ProxyShared};
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
    /// Path to the bootstrap node config (TOML). Required, except when
    /// checking a dynamic config on its own with `--dynamic-config`.
    #[arg(long, required_unless_present = "dynamic_config")]
    config: Option<PathBuf>,
    /// Validate the bootstrap and dynamic config, then exit.
    #[arg(long)]
    check_config: bool,
    /// With `--check-config`: validate this dynamic config instead of the one
    /// named by the bootstrap config, so a candidate file can be checked
    /// before it replaces the deployed one. Without `--config`, only this
    /// file is checked.
    #[arg(long, requires = "check_config", value_name = "FILE")]
    dynamic_config: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Load and validate config before doing anything else.
    let node = args
        .config
        .as_deref()
        .map(|path| {
            gfe_config::load_node_config(path)
                .with_context(|| format!("loading node config {}", path.display()))
        })
        .transpose()?;
    let dynamic_path = args
        .dynamic_config
        .as_ref()
        .or(node.as_ref().map(|node| &node.control_plane.config_file))
        .context("either --config or --dynamic-config is required")?;
    let dynamic = gfe_config::load_dynamic_config(dynamic_path)
        .with_context(|| format!("loading dynamic config {}", dynamic_path.display()))?;
    gfe_config::validate(&dynamic).context("validating dynamic config")?;

    if args.check_config {
        // Loading the certificates is part of applying a config, so a config
        // whose certificates cannot be loaded is not "OK".
        CertStore::build(&dynamic.certificates).context("loading certificates")?;
        println!(
            "config OK: {} listeners, {} routes, {} pools, {} certificates",
            dynamic.listeners.len(),
            dynamic.routes.len(),
            dynamic.pools.len(),
            dynamic.certificates.len()
        );
        return Ok(());
    }

    let node = node.context("--config is required to run a node")?;
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
        upstream: build_upstream_client(&node.upstream, &node.timeouts)?,
        metrics: metrics.clone(),
        limits: node.limits.clone(),
        timeouts: node.timeouts.clone(),
        tls: node.tls.clone(),
        draining: AtomicBool::new(false),
    });

    // The TLS server config is shared across https listeners. Cert rotation
    // flows through the resolver's swappable store, so it is never rebuilt.
    let server_config = Arc::new(
        gfe_tls::server_config(resolver.clone(), node.tls.min_version)
            .map_err(|e| anyhow::anyhow!("building TLS server config: {e}"))?,
    );

    // Readiness + drain plumbing. The ops server reads `draining` from the
    // shared state; the listeners watch the drain controller's channel.
    let ready = Arc::new(AtomicBool::new(false));
    let drain = DrainController::new();
    let listeners = Arc::new(ListenerSet::new(
        shared.clone(),
        server_config,
        drain.subscribe(),
    ));

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

    // Start the control plane: initial config load/apply (with cache
    // fallback), listeners, health probes, last-known-good cache, and the
    // hot-reload watchers. Fails fast if a listener cannot be bound.
    let mut controller = Controller::new(shared.clone(), listeners.clone(), &node);
    controller
        .start()
        .map_err(|e| anyhow::anyhow!("starting controller: {e}"))?;

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
    tracing::info!("gfe-node ready");

    listeners.serve_until_drained().await;

    controller.shutdown();
    tracing::info!("gfe-node stopped");
    Ok(())
}

/// Build the upstream client from the node's `[upstream]` config (idle pool
/// size, optional extra CA bundle, optional mTLS client certificate) and the
/// `upstream_connect` timeout.
fn build_upstream_client(
    cfg: &gfe_types::UpstreamConfig,
    timeouts: &gfe_types::TimeoutsConfig,
) -> Result<UpstreamClient> {
    fn read(p: &Path) -> Result<Vec<u8>> {
        std::fs::read(p).with_context(|| format!("reading {}", p.display()))
    }
    let opts = UpstreamClientOptions {
        idle_per_host: cfg.idle_per_host.unwrap_or(32),
        client_cert_pem: cfg.client_cert_file.as_deref().map(read).transpose()?,
        client_key_pem: cfg.client_key_file.as_deref().map(read).transpose()?,
        extra_ca_pem: cfg.extra_ca_file.as_deref().map(read).transpose()?,
        connect_timeout: Some(timeouts.upstream_connect),
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
