//! `gfe-node`, the binary a node runs: the reverse proxy of `gfe-proxy`, its
//! ops endpoints, and the process around them (the command line, the log,
//! signals, systemd, and the upgrade in place).

mod ops;

use anyhow::{Context, Result};
use clap::Parser;
use gfe_config::NodeConfig;
use gfe_node::signals::{Request, Signals};
use gfe_node::systemd;
use gfe_node::upgrade::{self, Inherited, Predecessor};
use gfe_proxy::Frontend;
use netkit_observability::{GfeMetrics, Log};
use ops::Ops;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::watch;

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
            gfe_config::load_node_config(path)
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
    // front end does, and falls back to the last-known-good cache if the
    // deployed file cannot be used.
    let node = node.context("--config is required to run a node")?;
    // Kept to the end: dropping it writes out the lines still queued. It
    // also carries the records of Pingora, which logs through the `log`
    // crate: starting it installs the bridge from `log` to `tracing`.
    let log = Arc::new(Log::start(node.log.file.as_deref())?);
    for deprecation in node.deprecations() {
        tracing::warn!("{deprecation}");
    }
    let (predecessor, inherited) = if args.upgrade {
        let (predecessor, inherited) = upgrade::take_over()?;
        (Some(predecessor), inherited)
    } else {
        (None, Inherited::default())
    };

    // Pingora finds this runtime as the current one: the node does not run
    // Pingora's own server.
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
    let dynamic = gfe_config::load_dynamic_config(path)
        .with_context(|| format!("loading dynamic config {}", path.display()))?;
    Frontend::check(&dynamic).context("checking dynamic config")?;
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
    node: NodeConfig,
    predecessor: Option<Predecessor>,
    inherited: Inherited,
    log: Arc<Log>,
) -> Result<()> {
    tracing::info!(node = %node.node.id, "starting gfe-node");

    // Before anything is served: a signal must find the node listening for
    // it, or it kills the process.
    let mut signals = Signals::install().context("installing signal handlers")?;
    let metrics = Arc::new(GfeMetrics::new());
    let ops = Arc::new(Ops::new(metrics.clone(), log));

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
            tokio::spawn(ops::serve(socket.clone(), ops.clone(), ops_stopped));
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

    // The proxy: the kernel view, the initial config (with cache fallback),
    // the listeners (the inherited sockets first), the health probes and
    // the hot-reload watchers. Fails fast if a listener cannot be bound.
    let frontend = Arc::new(
        Frontend::start(&node, metrics.clone(), inherited.listeners)
            .context("starting the proxy")?,
    );

    ops.serving(frontend.clone());
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
                    handed_over = hand_over(&frontend, ops) => handed_over,
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
                        frontend.stop_kernel_view();
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

    // Stops following config changes first: applying one would make a
    // leaving node listen again.
    frontend.drain().await;
    tracing::info!("gfe-node stopped");
    Ok(())
}

/// Hand the proxy's listening sockets and the ops socket (`ops`, with the
/// address it is configured on) to a successor; its process id. Failing to
/// duplicate the sockets is a failed upgrade like any other: the node goes
/// on serving.
async fn hand_over(
    frontend: &Frontend,
    ops: Option<(SocketAddr, &tokio::net::TcpListener)>,
) -> Result<u32> {
    let sockets = frontend
        .sockets()
        .context("duplicating the listening sockets")?;
    upgrade::hand_over(sockets, ops).await
}

/// Wait for a request to stop, while an upgrade is under way: another
/// request to upgrade is ignored.
async fn stop_requested(signals: &mut Signals) {
    while signals.next().await != Request::Stop {
        tracing::warn!("upgrade requested while one is under way, ignored");
    }
}
