//! The GFE L7 proxy (data plane).
//!
//! Ties together the route table, certificate resolver, upstream pools, the
//! shared health map, and the pooled upstream client. The control plane
//! mutates the snapshots via the `ArcSwap`s and the [`SniResolver`], and
//! reconciles the listening sockets through the [`ListenerSet`]; the proxy
//! reads the snapshots lock-free on the hot path.

pub mod acceptor;
pub mod activity;
pub mod conn_record;
pub mod connection;
pub mod drain;
pub mod errors;
pub mod forward;
pub mod listeners;
pub mod progress;
pub mod record;
pub mod service;

pub use drain::DrainController;
pub use errors::RespBody;
pub use listeners::ListenerSet;

use arc_swap::ArcSwap;
use gfe_core::config::{LimitsConfig, ListenerId, TimeoutsConfig, TlsConfig};
use gfe_observability::GfeMetrics;
use gfe_router::RouteTable;
use gfe_tls::{CertStore, ChallengeStore, SniResolver};
use gfe_upstream::{HealthMap, PoolSet, UpstreamClient};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

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
    /// The kernel's view of the accept queue, where one is available.
    pub accept_queue: Option<Arc<dyn AcceptQueue>>,
}

/// What only the kernel knows about a connection the node has just accepted.
/// The proxy does not care where the answer comes from; the node provides an
/// implementation when it has one (eBPF) and none otherwise.
pub trait AcceptQueue: Send + Sync {
    /// How long the connection between `local` and `peer` had been waiting,
    /// its handshake complete, when `accept` returned it. `None` if unknown.
    fn waited(&self, local: SocketAddr, peer: SocketAddr) -> Option<Duration>;
}

impl ProxyShared {
    /// Shared state with nothing configured yet: no routes, pools or
    /// certificates, and every backend presumed healthy until probed. The
    /// control plane fills it in by applying a dynamic config.
    pub fn new(
        upstream: UpstreamClient,
        metrics: Arc<GfeMetrics>,
        limits: LimitsConfig,
        timeouts: TimeoutsConfig,
        tls: TlsConfig,
    ) -> Self {
        // Published next to the gauges they bound, so saturation is a ratio
        // of two series rather than a number hardcoded in a dashboard.
        metrics
            .proxy
            .connections_limit
            .set(limits.max_connections as i64);
        metrics
            .proxy
            .listener_connections_limit
            .set(limits.max_connections_listener as i64);
        ProxyShared {
            routes: ArcSwap::from_pointee(RouteTable::default()),
            pools: ArcSwap::from_pointee(PoolSet::default()),
            resolver: Arc::new(SniResolver::new(CertStore::default())),
            challenges: Arc::new(ChallengeStore::new()),
            health: Arc::new(HealthMap::new(true)),
            upstream,
            metrics,
            limits,
            timeouts,
            tls,
            draining: AtomicBool::new(false),
            accept_queue: None,
        }
    }

    /// Ask `accept_queue` how long each accepted connection waited.
    pub fn with_accept_queue(mut self, accept_queue: Arc<dyn AcceptQueue>) -> Self {
        self.accept_queue = Some(accept_queue);
        self
    }
}

/// What request handling knows about the connection a request arrived on.
#[derive(Clone)]
pub struct ConnCtx {
    pub shared: Arc<ProxyShared>,
    /// The id of the listener the request arrived on, as configured when it
    /// arrived: a reload may rename a listener while its connections stay
    /// open.
    pub listener_id: ListenerId,
    pub is_tls: bool,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub sni: Option<String>,
    /// The negotiated TLS parameters, on a TLS connection.
    pub tls: Option<conn_record::TlsInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publishes_connection_limits_as_gauges() {
        let metrics = Arc::new(GfeMetrics::new());
        let limits = LimitsConfig {
            max_connections: 7,
            max_connections_listener: 3,
            ..Default::default()
        };

        ProxyShared::new(
            UpstreamClient::new(1).unwrap(),
            metrics.clone(),
            limits,
            TimeoutsConfig::default(),
            TlsConfig::default(),
        );

        let exposed = metrics.encode();
        assert!(exposed.contains("gfe_connections_limit 7"), "{exposed}");
        assert!(
            exposed.contains("gfe_listener_connections_limit 3"),
            "{exposed}"
        );
    }
}
