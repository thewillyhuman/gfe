//! The GFE L7 proxy (data plane).
//!
//! Ties together the route table, certificate resolver, upstream pools, the
//! shared health map, and the pooled upstream client. The control plane
//! mutates the snapshots via the `ArcSwap`s and the [`SniResolver`], and
//! reconciles the listening sockets through the [`ListenerSet`]; the proxy
//! reads the snapshots lock-free on the hot path.

pub mod acceptor;
pub mod activity;
pub mod connection;
pub mod drain;
pub mod errors;
pub mod forward;
pub mod listeners;
pub mod record;
pub mod service;

pub use drain::DrainController;
pub use errors::RespBody;
pub use listeners::ListenerSet;

use arc_swap::ArcSwap;
use gfe_metrics::GfeMetrics;
use gfe_router::RouteTable;
use gfe_tls::{CertStore, ChallengeStore, SniResolver};
use gfe_types::{LimitsConfig, ListenerId, TimeoutsConfig, TlsConfig};
use gfe_upstream::{HealthMap, PoolSet, UpstreamClient};
use std::net::IpAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

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
        }
    }
}

/// Per-connection context passed to request handling.
pub struct ConnCtx {
    pub shared: Arc<ProxyShared>,
    pub listener_id: ListenerId,
    pub is_tls: bool,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub sni: Option<String>,
}
