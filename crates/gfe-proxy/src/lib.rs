//! The GFE L7 proxy (data plane).
//!
//! Ties together the route table, certificate resolver, upstream pools, the
//! shared health map, and the pooled upstream client. The control plane
//! mutates the snapshots via the `ArcSwap`s and the [`SniResolver`], and
//! reconciles the listening sockets through the [`ListenerSet`]; the proxy
//! reads the snapshots lock-free on the hot path.

pub mod errors;
pub mod forward;
pub mod progress;
pub mod record;
pub mod reload;
pub mod routing;
pub mod service;

pub use errors::RespBody;

use crate::routing::RouteTable;
use arc_swap::ArcSwap;
use gfe_core::config::{ListenerId, TlsConfig};
use gfe_core::server::{ConnInfo, RequestHandler, ServerShared, TlsInfo};
use gfe_core::tls::{CertStore, ChallengeStore, SniResolver};
use gfe_core::upstream::UpstreamClient;
use gfe_health_checking::HealthMap;
use gfe_load_balancing::PoolSet;
use hyper::body::Incoming;
use hyper::{Request, Response};
use std::net::IpAddr;
use std::sync::Arc;

/// The listeners of a node whose requests the proxy answers.
pub type ListenerSet = gfe_core::server::ListenerSet<ProxyShared>;

/// Shared state read by the data plane and mutated by the control plane.
pub struct ProxyShared {
    /// What every connection shares, whatever its requests are: metrics,
    /// limits, timeouts and whether the node is draining.
    pub server: Arc<ServerShared>,
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
    pub tls: TlsConfig,
}

impl ProxyShared {
    /// Shared state with nothing configured yet: no routes, pools or
    /// certificates, and every backend presumed healthy until probed. The
    /// control plane fills it in by applying a dynamic config.
    pub fn new(server: Arc<ServerShared>, upstream: UpstreamClient, tls: TlsConfig) -> Self {
        ProxyShared {
            server,
            routes: ArcSwap::from_pointee(RouteTable::default()),
            pools: ArcSwap::from_pointee(PoolSet::default()),
            resolver: Arc::new(SniResolver::new(CertStore::default())),
            challenges: Arc::new(ChallengeStore::new()),
            health: Arc::new(HealthMap::new(true)),
            upstream,
            tls,
        }
    }
}

impl RequestHandler for ProxyShared {
    async fn handle(
        self: &Arc<Self>,
        conn: ConnInfo,
        req: Request<Incoming>,
    ) -> Response<RespBody> {
        let ctx = Arc::new(ConnCtx {
            shared: self.clone(),
            listener_id: conn.listener_id,
            is_tls: conn.is_tls,
            client_ip: conn.client_ip,
            client_port: conn.client_port,
            sni: conn.sni,
            tls: conn.tls,
        });
        let Ok(response) = service::handle_request(ctx, req).await;
        response
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
    pub tls: Option<TlsInfo>,
}
