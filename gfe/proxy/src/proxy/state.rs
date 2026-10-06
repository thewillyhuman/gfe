//! What the proxy reads on every request, shared by all of them.

use crate::listener::Connections;
use crate::metrics::GfeMetrics;
use crate::proxy::connection_cap::ConnectionCap;
use crate::proxy::error::ProxyError;
use crate::proxy::peer::{UpstreamTls, Waits};
use crate::routing::RouteTable;
use arc_swap::ArcSwap;
use gfe_config::{NodeConfig, Scheme, TimeoutsConfig};
use netkit_health_checking::HealthMap;
use netkit_load_balancing::PoolSet;
use netkit_tls::{CertStore, SniResolver};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// How long the address a backend's name resolved to is trusted.
const BACKEND_ADDRESS_TTL: Duration = Duration::from_secs(10);

/// What a config is compiled into for the proxy: the routes and the pools
/// they forward to. Swapped as one, so that no request sees routes of one
/// config with the pools of another.
#[derive(Default)]
pub(crate) struct Routing {
    pub(crate) routes: RouteTable,
    /// Each pool carries the scheme its backends are spoken to in.
    pub(crate) pools: PoolSet<Scheme>,
}

/// What every request reads: the route table and the pools (swapped by a
/// reload), the certificate store (for the host rules), the health of the
/// backends, the node's settings, its metrics and the connections it serves.
///
/// The routes and pools are behind an `ArcSwap`, loaded once per request and
/// never held across an await. The rest is fixed for the life of the
/// process, or shared with whoever keeps it current (the resolver's store,
/// the health map).
pub struct State {
    pub(crate) routing: ArcSwap<Routing>,
    resolver: Arc<SniResolver>,
    health: Arc<HealthMap>,
    metrics: Arc<GfeMetrics>,
    connections: Arc<Connections>,
    /// The node's shutdown signal: `true` once it drains.
    drain: watch::Receiver<bool>,
    /// The `Strict-Transport-Security` value of responses over TLS; empty
    /// for none.
    pub(crate) hsts: String,
    pub(crate) timeouts: TimeoutsConfig,
    pub(crate) max_header_bytes: usize,
    pub(crate) max_h2_concurrent_streams: u32,
    /// Idle upstream connections kept, over all backends.
    pub(crate) idle_connections: usize,
    /// The worker threads of the node's runtime.
    pub(crate) worker_threads: usize,
    pub(crate) waits: Waits,
    pub(crate) upstream_tls: UpstreamTls,
    pub(crate) cap: Arc<ConnectionCap>,
    pub(crate) dns: netkit_dns::Cache,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("routes", &self.routing.load().routes.route_count())
            .field("timeouts", &self.timeouts)
            .finish_non_exhaustive()
    }
}

impl State {
    /// The state of a node configured by `config`, with no routes, pools or
    /// certificates yet (a reload installs them, see [`State::swap`]) and
    /// every backend presumed healthy until probed. Loads the upstream TLS
    /// files `[upstream]` names, and fails, naming the file, if one cannot
    /// be used.
    ///
    /// `drain` is the node's shutdown signal
    /// ([`Drain::subscribe`](crate::listener::Drain::subscribe)): while it is
    /// `true`, responses end keep-alive.
    pub fn new(
        config: &NodeConfig,
        metrics: Arc<GfeMetrics>,
        connections: Arc<Connections>,
        drain: watch::Receiver<bool>,
    ) -> Result<Arc<State>, ProxyError> {
        let limits = &config.limits;
        let upstream_tls = UpstreamTls::load(&config.upstream)?;
        metrics
            .proxy
            .upstream_connections_limit
            .set(i64::try_from(limits.max_upstream_connections).unwrap_or(i64::MAX));
        let cap = ConnectionCap::new(
            limits.max_upstream_connections,
            metrics.proxy.upstream_connections.clone(),
        );
        let worker_threads = match config.node.worker_threads {
            0 => std::thread::available_parallelism().map_or(1, |n| n.get()),
            n => n,
        };
        Ok(Arc::new(State {
            routing: ArcSwap::from_pointee(Routing::default()),
            resolver: Arc::new(SniResolver::new(CertStore::default())),
            health: Arc::new(HealthMap::new(true)),
            metrics,
            connections,
            drain,
            hsts: config.tls.hsts.clone(),
            timeouts: config.timeouts.clone(),
            max_header_bytes: limits.max_header_bytes,
            max_h2_concurrent_streams: limits.max_h2_concurrent_streams,
            idle_connections: config.upstream.idle_connections,
            worker_threads,
            waits: Waits {
                connect: config.timeouts.upstream_connect,
                first_byte: config.timeouts.upstream_first_byte,
                idle: config.upstream.idle_timeout,
            },
            upstream_tls,
            cap,
            dns: netkit_dns::Cache::new(netkit_dns::SystemResolver, BACKEND_ADDRESS_TTL),
        }))
    }

    /// Install a new route table and pool set, atomically: requests that
    /// have already been routed finish against the old ones.
    pub fn swap(&self, routes: RouteTable, pools: PoolSet<Scheme>) {
        self.routing.store(Arc::new(Routing { routes, pools }));
    }

    /// The SNI resolver, whose certificate store a reload swaps. The edge
    /// terminates TLS with it; the proxy checks the host rules against it.
    pub fn resolver(&self) -> &Arc<SniResolver> {
        &self.resolver
    }

    /// The health of the backends, kept up to date by the health checker.
    pub fn health(&self) -> &Arc<HealthMap> {
        &self.health
    }

    /// The node's metrics.
    pub fn metrics(&self) -> &Arc<GfeMetrics> {
        &self.metrics
    }

    /// The connections the node serves, which the edge registers.
    pub fn connections(&self) -> &Arc<Connections> {
        &self.connections
    }

    /// Whether the node drains. The value is read without waiting, and no
    /// lock is held past the call.
    pub(crate) fn is_draining(&self) -> bool {
        *self.drain.borrow()
    }
}
