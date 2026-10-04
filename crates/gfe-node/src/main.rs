//! `gfe-node` — the main GFE binary: runs the proxy (data plane) and the
//! control-plane pieces (config load/apply, ops server) on one box.

mod kernel;
mod ops;
mod signals;
mod systemd;
mod upgrade;

use anyhow::{Context, Result};
use clap::Parser;
use gfe_controller::Controller;
use gfe_core::upstream::{KeepAlive, UpstreamClient, UpstreamClientOptions};
use gfe_observability::{GfeMetrics, Log};
use gfe_proxy::{DrainController, ListenerSet, ProxyShared, ServerShared};
use ops::OpsState;
use signals::{Request, Signals};
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::watch;
use upgrade::{Inherited, Predecessor};

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
    /// Take over from the running node that started this process: listen on
    /// the sockets it passes on standard input instead of binding them, and
    /// tell it when it may stop. Passed by a node that upgrades itself, not
    /// by hand.
    #[arg(long, conflicts_with = "check_config")]
    upgrade: bool,
    /// With `--upgrade`: this process is no longer a child of the node it
    /// takes over from. Passed by this binary to itself.
    #[arg(long, requires = "upgrade", hide = true)]
    detached: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.upgrade && !args.detached {
        // Before anything else, the config included: all this process does
        // is start the successor and get out of its way.
        return upgrade::detach();
    }

    let node = args
        .config
        .as_deref()
        .map(|path| {
            gfe_core::config::load_node_config(path)
                .with_context(|| format!("loading node config {}", path.display()))
        })
        .transpose()?;

    if args.check_config {
        let dynamic_path = args
            .dynamic_config
            .as_ref()
            .or(node.as_ref().map(|node| &node.control_plane.config_file))
            .context("either --config or --dynamic-config is required")?;
        return check_dynamic_config(dynamic_path);
    }

    // A node being started does not read the dynamic config here: the
    // controller does, and falls back to the last-known-good cache if the
    // deployed file cannot be used.
    let node = node.context("--config is required to run a node")?;
    // Kept to the end: dropping it writes out the lines still queued.
    let log = Arc::new(Log::start(node.log.file.as_deref())?);
    let (predecessor, inherited) = if args.upgrade {
        let (predecessor, inherited) = upgrade::take_over()?;
        (Some(predecessor), inherited)
    } else {
        (None, Inherited::default())
    };

    let mut rt = tokio::runtime::Builder::new_multi_thread();
    rt.enable_all();
    if node.node.worker_threads > 0 {
        rt.worker_threads(node.node.worker_threads);
    }
    let rt = rt.build().context("building tokio runtime")?;
    rt.block_on(run(node, predecessor, inherited, log.clone()))
}

/// Check a dynamic config the way a node would before applying it: parse it,
/// then everything a reload does short of swapping it in (validate, load the
/// certificates, compile the routes, build the pools).
fn check_dynamic_config(path: &Path) -> Result<()> {
    let dynamic = gfe_core::config::load_dynamic_config(path)
        .with_context(|| format!("loading dynamic config {}", path.display()))?;
    gfe_config::prepare(&dynamic).context("checking dynamic config")?;
    println!(
        "config OK: {} listeners, {} routes, {} pools, {} certificates",
        dynamic.listeners.len(),
        dynamic.routes.len(),
        dynamic.pools.len(),
        dynamic.certificates.len()
    );
    Ok(())
}

/// Run a node until it is told to stop. `inherited` are the listening sockets
/// it starts with, and `predecessor` the node it took them from, if any.
async fn run(
    node: gfe_core::config::NodeConfig,
    predecessor: Option<Predecessor>,
    inherited: Inherited,
    log: Arc<Log>,
) -> Result<()> {
    tracing::info!(node = %node.node.id, vip = %node.node.loopback_vip, "starting gfe-node");

    // Before anything is served: a signal must find the node listening for
    // it, or it kills the process.
    let mut signals = Signals::install().context("installing signal handlers")?;
    let metrics = Arc::new(GfeMetrics::new());

    // The kernel's view of the node's connections, if enabled and available.
    let kernel = kernel::attach(&node, &metrics);

    let mut server = ServerShared::new(metrics.clone(), node.limits.clone(), node.timeouts.clone());
    if let Some((view, _)) = &kernel {
        server = server.with_accept_queue(view.clone());
    }
    // The shared data-plane state starts empty; the controller fills it in.
    let shared = Arc::new(ProxyShared::new(
        Arc::new(server),
        build_upstream_client(&node.upstream, &node.timeouts, &node.limits)?,
        node.tls.clone(),
    ));
    let resolver = shared.resolver.clone();

    // The TLS server config is shared across https listeners. Cert rotation
    // flows through the resolver's swappable store, so it is never rebuilt.
    let server_config = Arc::new(
        gfe_core::tls::server_config(resolver.clone(), node.tls.min_version)
            .map_err(|e| anyhow::anyhow!("building TLS server config: {e}"))?,
    );

    // Readiness + drain plumbing. The ops server reads `draining` from the
    // shared state; the listeners watch the drain controller's channel.
    let ready = Arc::new(AtomicBool::new(false));
    let drain = DrainController::new();
    let listeners = Arc::new(ListenerSet::new(
        shared.server.clone(),
        shared.clone(),
        server_config,
        drain.subscribe(),
    ));
    if predecessor.is_some() {
        tracing::info!(
            listeners = inherited.listeners.len(),
            "taking over the listening sockets of the running node"
        );
    }
    listeners.adopt(inherited.listeners);

    // Ops server.
    let ops_state = Arc::new(OpsState {
        metrics: metrics.clone(),
        ready: ready.clone(),
        shared: shared.clone(),
        kernel: kernel.as_ref().map(|(view, _)| view.clone()),
        log,
    });
    let kernel_reporting = kernel.map(|(_, closed)| {
        tokio::spawn(kernel::report(closed, listeners.clone(), metrics.clone()))
    });
    // A node without its ops endpoints still serves traffic, so not being
    // able to listen for them is reported and lived with.
    let ops_addr = node.node.metrics_addr;
    let ops_socket = match ops::listen(ops_addr, inherited.ops).await {
        Ok(socket) => Some(Arc::new(socket)),
        Err(e) => {
            tracing::error!(error = %e, "ops server failed");
            None
        }
    };
    let (stop_ops, ops_stopped) = watch::channel(false);
    let serve_ops = || {
        if let Some(socket) = &ops_socket {
            tokio::spawn(ops::serve(socket.clone(), ops_state.clone(), ops_stopped));
        }
    };
    // A node that takes over shares the ops socket with the running node,
    // which is ready: answering "not ready" next to it until this one is
    // would have the node withdrawn by whoever probes it.
    let serve_ops_once_ready = if predecessor.is_some() {
        Some(serve_ops)
    } else {
        serve_ops();
        None
    };

    // Start the control plane: initial config load/apply (with cache
    // fallback), listeners, health probes, last-known-good cache, and the
    // hot-reload watchers. Fails fast if a listener cannot be bound.
    let mut controller = Controller::new(shared.clone(), listeners.clone(), &node);
    controller
        .start()
        .map_err(|e| anyhow::anyhow!("starting controller: {e}"))?;

    ready.store(true, Ordering::SeqCst);
    if let Some(serve_ops) = serve_ops_once_ready {
        serve_ops();
    }
    tracing::info!("gfe-node ready");
    match predecessor {
        // Without this the predecessor does not stop: it gives up on this
        // node and goes on serving next to it. It is also the predecessor
        // that tells systemd, which only listens to the process it knows.
        Some(predecessor) => predecessor
            .release()
            .context("telling the running node that this one has taken over")?,
        None => systemd::ready(),
    }

    // Serve until told to stop, or until a successor has taken over.
    loop {
        match signals.next().await {
            Request::Stop => {
                tracing::info!("shutdown signal received, draining");
                break;
            }
            Request::Upgrade => {
                tracing::info!("upgrade requested, starting a successor");
                systemd::upgrading();
                let ops = ops_socket.as_deref().map(|socket| (ops_addr, socket));
                // A stop is not kept waiting for the successor: the service
                // manager kills a node that takes too long to stop, drained
                // or not.
                let handed_over = tokio::select! {
                    handed_over = upgrade::hand_over(&listeners, ops) => handed_over,
                    () = stop_requested(&mut signals) => {
                        tracing::info!("shutdown signal received, abandoning the upgrade and draining");
                        break;
                    }
                };
                match handed_over {
                    Ok(successor) => {
                        tracing::info!(successor, "the successor has taken over, draining");
                        systemd::upgraded(successor);
                        // The ops endpoints are the successor's from now on:
                        // answering next to it would mix two nodes' metrics.
                        let _ = stop_ops.send(true);
                        // So is the kernel's view: the two processes share a
                        // cgroup, and both would report every connection.
                        if let Some(reporting) = &kernel_reporting {
                            reporting.abort();
                        }
                        break;
                    }
                    Err(e) => {
                        let reason = format!("{e:#}");
                        tracing::error!(
                            error = reason,
                            "upgrade failed, this node goes on serving"
                        );
                        metrics.control.upgrade_failures.inc();
                        systemd::upgrade_failed(&reason);
                    }
                }
            }
        }
    }

    // A node that is leaving no longer follows config changes: applying one
    // would make it listen again.
    controller.shutdown();
    drop(controller);
    drain.trigger(&shared.server);
    listeners.serve_until_drained().await;
    tracing::info!("gfe-node stopped");
    Ok(())
}

/// Wait for a request to stop, while an upgrade is under way: another
/// request to upgrade is ignored.
async fn stop_requested(signals: &mut Signals) {
    while signals.next().await != Request::Stop {
        tracing::warn!("upgrade requested while one is under way, ignored");
    }
}

/// Build the upstream client from the node's `[upstream]` config (idle pool
/// size, optional extra CA bundle, optional mTLS client certificate) and the
/// `upstream_connect` timeout and `max_upstream_connections` limit.
fn build_upstream_client(
    cfg: &gfe_core::config::UpstreamConfig,
    timeouts: &gfe_core::config::TimeoutsConfig,
    limits: &gfe_core::config::LimitsConfig,
) -> Result<UpstreamClient> {
    fn read(p: &Path) -> Result<Vec<u8>> {
        std::fs::read(p).with_context(|| format!("reading {}", p.display()))
    }
    let opts = UpstreamClientOptions {
        idle_per_host: cfg.idle_per_host.unwrap_or(32),
        idle_timeout: Some(cfg.idle_timeout),
        client_cert_pem: cfg.client_cert_file.as_deref().map(read).transpose()?,
        client_key_pem: cfg.client_key_file.as_deref().map(read).transpose()?,
        extra_ca_pem: cfg.extra_ca_file.as_deref().map(read).transpose()?,
        connect_timeout: Some(timeouts.upstream_connect),
        max_connections: Some(limits.max_upstream_connections),
        // A backend that has been silent for as long as it may take to start
        // responding is asked for a sign of life, and has as long to give it
        // as it has to accept a connection.
        http2_keep_alive: Some(KeepAlive {
            idle: timeouts.upstream_first_byte,
            timeout: timeouts.upstream_connect,
        }),
    };
    UpstreamClient::with_options(opts).map_err(|e| anyhow::anyhow!("building upstream client: {e}"))
}
