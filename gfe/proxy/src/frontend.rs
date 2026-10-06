//! A running reverse proxy: the edge, the proxy, the config it follows, the
//! health checks of its backends and the kernel's view of its connections,
//! put together.
//!
//! This is what a node runs. The binary adds the process around it (the
//! command line, signals, the ops endpoint, the upgrade in place), and the
//! functional tests drive it directly, so that they test what a node runs.

use crate::kernel::{self, KernelView};
use crate::listener::{Connections, Drain, Listeners, Shared};
use crate::proxy::{self, App, ProxyError, State};
use crate::reload::{self, CERT_POLL_INTERVAL, Controller, ReloadError};
use gfe_config::{DynamicConfig, ListenerId, NodeConfig};
use netkit_observability::GfeMetrics;
use netkit_tls::{Acceptor, TlsError};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::task::JoinHandle;

/// Why a front end could not start. Nothing is served when it fails.
#[derive(Debug, Error)]
pub enum StartError {
    /// The bootstrap config names upstream TLS files that cannot be used.
    #[error(transparent)]
    Proxy(#[from] ProxyError),
    /// The TLS policy cannot be built.
    #[error(transparent)]
    Tls(#[from] TlsError),
    /// Neither the deployed dynamic config nor the last-known-good cache can
    /// be applied, or the config file cannot be watched.
    #[error(transparent)]
    Config(#[from] ReloadError),
}

/// A reverse proxy serving, from [`start`] until it has drained.
///
/// [`start`]: Frontend::start
pub struct Frontend {
    state: Arc<State>,
    shared: Arc<Shared>,
    listeners: Arc<Listeners<App>>,
    drain: Drain,
    controller: Controller,
    kernel: Option<Arc<KernelView>>,
    kernel_reporting: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Frontend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frontend")
            .field("draining", &self.is_draining())
            .field("kernel_view", &self.kernel.is_some())
            .finish_non_exhaustive()
    }
}

impl Frontend {
    /// Start serving as `node` says, counting in `metrics`. `inherited` are
    /// the listening sockets taken over from the node this one replaces
    /// (none for a fresh start), each with the address it is configured on:
    /// they are used instead of binding those addresses.
    ///
    /// Attaches the kernel view (or says why it cannot), applies the
    /// deployed dynamic config or the last-known-good cache (see
    /// [`Controller::start`]), starts the health checks, and follows the
    /// config file and its certificate files from then on. A config is
    /// validated and built before any inherited socket is touched.
    ///
    /// Must be called from within a Tokio runtime.
    pub fn start(
        node: &NodeConfig,
        metrics: Arc<GfeMetrics>,
        inherited: Vec<(SocketAddr, std::net::TcpListener)>,
    ) -> Result<Frontend, StartError> {
        Frontend::start_polling_certificates_every(node, metrics, inherited, CERT_POLL_INTERVAL)
    }

    /// [`Frontend::start`], checking the certificate files for a rotation
    /// every `cert_poll_interval` instead of every
    /// [`CERT_POLL_INTERVAL`]: for tests, which cannot wait 10 seconds.
    #[doc(hidden)]
    pub fn start_polling_certificates_every(
        node: &NodeConfig,
        metrics: Arc<GfeMetrics>,
        inherited: Vec<(SocketAddr, std::net::TcpListener)>,
        cert_poll_interval: Duration,
    ) -> Result<Frontend, StartError> {
        let kernel = kernel::attach(node, &metrics);
        let drain = Drain::new();
        let state = State::new(
            node,
            Arc::clone(&metrics),
            Connections::new(),
            drain.subscribe(),
        )?;
        let mut shared = Shared::new(
            Arc::clone(&metrics),
            node.limits.clone(),
            node.timeouts.clone(),
        )
        .with_sni_resolver(Arc::clone(state.resolver()));
        if let Some((view, _)) = &kernel {
            shared = shared.with_accept_queue(Arc::clone(view) as _);
        }
        let shared = Arc::new(shared);
        // One TLS policy for every HTTPS listener. Certificates rotate
        // through the resolver's store, so it is never rebuilt.
        let tls = netkit_tls::server_config(
            Arc::clone(state.resolver()),
            tls_min_version(node.tls.min_version),
        )?;
        let listeners = Arc::new(Listeners::new(
            Arc::clone(&shared),
            proxy::app(Arc::clone(&state)),
            Acceptor::new(Arc::new(tls)),
            Arc::clone(state.connections()),
            drain.subscribe(),
        ));
        if !inherited.is_empty() {
            tracing::info!(
                listeners = inherited.len(),
                "taking over the listening sockets of the running node"
            );
        }
        listeners.adopt(inherited);

        let controller = Controller::start(
            Arc::clone(&state),
            Arc::clone(&listeners),
            node,
            cert_poll_interval,
        )?;

        let (kernel, kernel_reporting) = match kernel {
            Some((view, closed)) => {
                let reporting =
                    tokio::spawn(kernel::report(closed, Arc::clone(&listeners), metrics));
                (Some(view), Some(reporting))
            }
            None => (None, None),
        };
        Ok(Frontend {
            state,
            shared,
            listeners,
            drain,
            controller,
            kernel,
            kernel_reporting,
        })
    }

    /// Check `config` the way a reload would before applying it: validate
    /// it, load its certificates, compile its routes and build its pools.
    /// What `--check-config` runs. Its listeners are not bound.
    pub fn check(config: &DynamicConfig) -> Result<(), ReloadError> {
        reload::prepare(config).map(drop)
    }

    /// Whether the node drains: `/readyz` then fails.
    pub fn is_draining(&self) -> bool {
        self.shared.is_draining()
    }

    /// A duplicate of every listening socket, with the address its listener
    /// is configured on, to hand to a successor. A duplicate keeps queueing
    /// connections after this node stops accepting.
    pub fn sockets(&self) -> io::Result<Vec<(SocketAddr, std::net::TcpListener)>> {
        self.listeners.sockets()
    }

    /// The address listener `id` is bound to, if it is running. Tells which
    /// port a listener configured on port 0 got.
    pub fn local_addr(&self, id: &ListenerId) -> Option<SocketAddr> {
        self.listeners.local_addr(id)
    }

    /// Bring up to date the metrics that are sampled rather than counted as
    /// things happen: what the kernel view could not report. Call it before
    /// each scrape.
    pub fn refresh_metrics(&self) {
        if let Some(kernel) = &self.kernel {
            let lost = i64::try_from(kernel.lost_events()).unwrap_or(i64::MAX);
            self.state.metrics().kernel.ebpf_lost_events.set(lost);
        }
    }

    /// Stop reporting the kernel's view of the node's connections. After an
    /// upgrade in place the successor reports it: the two processes share a
    /// cgroup, and both would report every connection.
    pub fn stop_kernel_view(&self) {
        if let Some(reporting) = &self.kernel_reporting {
            reporting.abort();
        }
    }

    /// Drain: stop following config changes (applying one would make a
    /// leaving node listen again), fail readiness, stop accepting, ask the
    /// clients to leave, and return once the last connection has closed or
    /// the drain deadline has elapsed (what is still open then is cut).
    pub async fn drain(&self) {
        self.controller.shutdown();
        self.drain.trigger(&self.shared);
        self.listeners.serve_until_drained().await;
    }
}

/// The library's name for the `[tls] min_version` of the node config.
fn tls_min_version(min_version: gfe_config::MinVersion) -> netkit_tls::MinVersion {
    match min_version {
        gfe_config::MinVersion::Tls12 => netkit_tls::MinVersion::Tls12,
        gfe_config::MinVersion::Tls13 => netkit_tls::MinVersion::Tls13,
    }
}

#[cfg(test)]
#[path = "frontend_test.rs"]
mod tests;
