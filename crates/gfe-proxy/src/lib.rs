//! The GFE L7 proxy engine (data plane).
//!
//! Ties together the route table, certificate resolver, upstream pools, the
//! shared health map, and the pooled upstream client. The control plane
//! mutates the snapshots via the `ArcSwap`s and the [`SniResolver`]; the proxy
//! reads them lock-free on the hot path.

pub mod acceptor;
pub mod connection;
pub mod drain;
pub mod errors;
pub mod forward;
pub mod service;

pub use drain::DrainController;
pub use errors::RespBody;

use arc_swap::ArcSwap;
use gfe_metrics::GfeMetrics;
use gfe_router::RouteTable;
use gfe_tls::{ChallengeStore, SniResolver};
use gfe_types::{LimitsConfig, Listener, ListenerId, TimeoutsConfig, TlsConfig};
use gfe_upstream::{HealthMap, PoolSet, UpstreamClient};
use rustls::ServerConfig;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};

/// Shared state read by the data plane and mutated by the control plane.
pub struct ProxyShared {
    /// Compiled route table, swapped atomically on reload.
    pub routes: ArcSwap<RouteTable>,
    /// Upstream pool set, swapped atomically on reload.
    pub pools: ArcSwap<PoolSet>,
    /// SNI certificate resolver (holds its own swappable cert store).
    pub resolver: Arc<SniResolver>,
    /// ACME http-01 challenge store, served on the plaintext HTTP listener.
    pub challenges: Arc<ChallengeStore>,
    /// Shared backend health, read on each upstream selection.
    pub health: Arc<HealthMap>,
    /// Pooled upstream client.
    pub upstream: UpstreamClient,
    /// Metrics.
    pub metrics: Arc<GfeMetrics>,
    pub limits: LimitsConfig,
    pub timeouts: TimeoutsConfig,
    pub tls: TlsConfig,
    /// Set when the node is draining (fails `/readyz`).
    pub draining: AtomicBool,
}

/// Per-connection context passed to request handling.
pub struct ConnCtx {
    pub shared: Arc<ProxyShared>,
    pub listener_id: ListenerId,
    pub is_tls: bool,
    pub client_ip: IpAddr,
    pub sni: Option<String>,
}

/// The proxy engine: binds listeners and serves connections.
pub struct ProxyEngine {
    shared: Arc<ProxyShared>,
}

impl ProxyEngine {
    pub fn new(shared: Arc<ProxyShared>) -> Self {
        ProxyEngine { shared }
    }

    pub fn shared(&self) -> &Arc<ProxyShared> {
        &self.shared
    }

    /// Bind all listeners up front so binding failures surface before we mark
    /// the node ready. Returns the bound sockets paired with their config.
    pub async fn bind(listeners: &[Listener]) -> std::io::Result<Vec<(Listener, TcpListener)>> {
        let mut out = Vec::with_capacity(listeners.len());
        for l in listeners {
            let addr = SocketAddr::new(l.address, l.port);
            let tcp = TcpListener::bind(addr).await?;
            tracing::info!(addr = %tcp.local_addr().unwrap_or(addr), id = %l.id, "listener bound");
            out.push((l.clone(), tcp));
        }
        Ok(out)
    }

    /// Serve the bound listeners until `shutdown` flips to `true`.
    pub async fn serve(
        &self,
        bound: Vec<(Listener, TcpListener)>,
        server_config: Arc<ServerConfig>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let global_sem = Arc::new(Semaphore::new(self.shared.limits.max_connections));
        let mut handles = Vec::new();

        for (listener, tcp) in bound {
            let cfg = if listener.is_tls() {
                Some(server_config.clone())
            } else {
                None
            };
            let shared = self.shared.clone();
            let gsem = global_sem.clone();
            let sd = shutdown.clone();
            handles.push(tokio::spawn(acceptor::run_listener(
                listener, tcp, shared, cfg, gsem, sd,
            )));
        }

        // Block until drain is signalled, then let accept loops wind down.
        let _ = shutdown.changed().await;
        for h in handles {
            let _ = h.await;
        }

        // Graceful drain: wait for in-flight connections to complete, bounded
        // by the drain deadline.
        let deadline = std::time::Instant::now() + self.shared.timeouts.drain_deadline;
        loop {
            let active = self.shared.metrics.proxy.connections_active.get();
            if active <= 0 || std::time::Instant::now() >= deadline {
                if active > 0 {
                    tracing::warn!(active, "drain deadline elapsed with connections still open");
                }
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}
