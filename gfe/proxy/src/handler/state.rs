//! What every request reads, shared by all of them: the routes and pools a
//! reload swaps, the certificates and backend health others keep current,
//! the node's settings, its metrics, and the client requests are sent to
//! backends with.
//!
//! What a request does with them is decided elsewhere.

use crate::handler::error::ProxyError;
use crate::metrics::GfeMetrics;
use crate::routing::RouteTable;
use arc_swap::ArcSwap;
use gfe_config::{NodeConfig, Scheme, TimeoutsConfig, UpstreamConfig};
use netkit_health_checking::HealthMap;
use netkit_http::client::{Client, KeepAlive, Options};
use netkit_load_balancing::PoolSet;
use netkit_tls::{CertStore, Connector, ConnectorOptions, Identity, SniResolver, Trust};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// How long the address a backend's name resolved to is trusted.
const BACKEND_ADDRESS_TTL: Duration = Duration::from_secs(10);

/// The idle connections kept per backend when `[upstream] idle_per_host`
/// is unset or 0: all of them. A cap below the requests in flight to a
/// backend makes the pool close a connection on every response beyond the
/// cap and dial a new one for the next request, with the churn, the
/// latency and the ephemeral ports that costs; what bounds idle connections
/// instead is `idle_timeout` and `max_upstream_connections`, as HAProxy
/// bounds them. `v1.1.0` kept 32.
const NO_IDLE_CAP: usize = usize::MAX;

/// What a config is compiled into for request handling: the routes and the
/// pools they forward to. Swapped as one, so that no request sees routes of
/// one config with the pools of another.
#[derive(Default)]
pub(crate) struct Routing {
    pub(crate) routes: RouteTable,
    /// Each pool carries the scheme its backends are spoken to in.
    pub(crate) pools: PoolSet<Scheme>,
}

/// What every request reads.
///
/// The routes and pools are behind an `ArcSwap`, loaded once per request
/// and never held across an await. The rest is fixed for the life of the
/// process, or shared with whoever keeps it current (the resolver's store,
/// the health map).
pub struct State {
    routing: ArcSwap<Routing>,
    resolver: Arc<SniResolver>,
    health: Arc<HealthMap>,
    metrics: Arc<GfeMetrics>,
    client: Client,
    /// The `Strict-Transport-Security` value of responses over TLS; empty
    /// for none.
    hsts: String,
    timeouts: TimeoutsConfig,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let routing = self.routing.load();
        f.debug_struct("State")
            .field("routes", &routing.routes.route_count())
            .field("pools", &routing.pools.len())
            .field("client", &self.client)
            .field("timeouts", &self.timeouts)
            .finish_non_exhaustive()
    }
}

impl State {
    /// The state of a node configured by `config`, counting in `metrics`,
    /// with no routes, pools or certificates yet (a reload installs them,
    /// see [`State::swap`]) and every backend presumed healthy until
    /// probed.
    ///
    /// Builds the client requests are sent to backends with, from
    /// `[upstream]`, `[timeouts]` and `[limits]`, and fails, naming the
    /// file, if an upstream TLS file cannot be used.
    pub fn new(config: &NodeConfig, metrics: Arc<GfeMetrics>) -> Result<Arc<State>, ProxyError> {
        let client = Client::new(client_options(config)?);
        let limit = config.limits.max_upstream_connections;
        metrics
            .proxy
            .upstream_connections_limit
            .set(i64::try_from(limit).unwrap_or(i64::MAX));
        Ok(Arc::new(State {
            routing: ArcSwap::from_pointee(Routing::default()),
            resolver: Arc::new(SniResolver::new(CertStore::default())),
            health: Arc::new(HealthMap::new(true)),
            metrics,
            client,
            hsts: config.tls.hsts.clone(),
            timeouts: config.timeouts.clone(),
        }))
    }

    /// Install a new route table and pool set, atomically: requests that
    /// have already been routed finish against the old ones.
    pub fn swap(&self, routes: RouteTable, pools: PoolSet<Scheme>) {
        self.routing.store(Arc::new(Routing { routes, pools }));
    }

    /// The SNI resolver, whose certificate store a reload swaps. The edge
    /// terminates TLS with it; the handler checks the host rules against it.
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

    /// Bring up to date the metrics that are sampled rather than counted as
    /// things happen: the upstream connections open, or being opened, now
    /// (`gfe_upstream_connections`). Call it before each scrape.
    pub fn refresh_metrics(&self) {
        let open = i64::try_from(self.client.open_connections()).unwrap_or(i64::MAX);
        self.metrics.proxy.upstream_connections.set(open);
    }

    /// The routes and pools now. A request loads them once, so that it is
    /// routed and forwarded by one config.
    pub(crate) fn routing(&self) -> Arc<Routing> {
        self.routing.load_full()
    }

    /// The client requests are sent to backends with.
    pub(crate) fn client(&self) -> &Client {
        &self.client
    }

    /// The `Strict-Transport-Security` value of responses over TLS; empty
    /// for none.
    pub(crate) fn hsts(&self) -> &str {
        &self.hsts
    }

    /// How long backends, and requests, may take.
    pub(crate) fn timeouts(&self) -> &TimeoutsConfig {
        &self.timeouts
    }
}

/// The options of the client requests are sent to backends with, as
/// `v1.1.0` built it from the node config.
///
/// A connection to an HTTP/2 backend silent for as long as the backend may
/// take to start responding (`upstream_first_byte`) is asked for a sign of
/// life, and has as long to give it as it has to be opened
/// (`upstream_connect`).
fn client_options(config: &NodeConfig) -> Result<Options, ProxyError> {
    let timeouts = &config.timeouts;
    Ok(Options {
        idle_per_host: match config.upstream.idle_per_host {
            None | Some(0) => NO_IDLE_CAP,
            Some(n) => n,
        },
        idle_timeout: Some(config.upstream.idle_timeout),
        connect_timeout: Some(timeouts.upstream_connect),
        http2_keep_alive: Some(KeepAlive {
            idle: timeouts.upstream_first_byte,
            timeout: timeouts.upstream_connect,
        }),
        max_connections: Some(config.limits.max_upstream_connections),
        tls: connector(&config.upstream)?,
        address_ttl: BACKEND_ADDRESS_TTL,
    })
}

/// TLS towards backends: the system's trust store plus `extra_ca_file`, and
/// the client certificate when one is configured. A file that cannot be
/// used is named in the error.
fn connector(upstream: &UpstreamConfig) -> Result<Connector, ProxyError> {
    let trust = match &upstream.extra_ca_file {
        Some(file) => Trust::SystemAnd(read(file, "extra_ca_file")?),
        None => Trust::System,
    };
    let identity = match (&upstream.client_cert_file, &upstream.client_key_file) {
        (Some(cert_file), Some(key_file)) => Some((
            cert_file,
            key_file,
            Identity {
                cert_chain_pem: read(cert_file, "client_cert_file")?,
                key_pem: read(key_file, "client_key_file")?,
            },
        )),
        (None, None) => None,
        _ => return Err(ProxyError::IncompleteClientCertificate),
    };
    // The trust alone first, so that a bundle that cannot be used is named
    // as such, and not taken for a fault of the client certificate.
    let trusted = Connector::new(ConnectorOptions {
        trust: trust.clone(),
        identity: None,
    })
    .map_err(|error| match &upstream.extra_ca_file {
        Some(file) => ProxyError::UpstreamTls {
            setting: "extra_ca_file",
            file: file.clone(),
            reason: error.to_string(),
        },
        None => ProxyError::Tls(error),
    })?;
    let Some((cert_file, key_file, identity)) = identity else {
        return Ok(trusted);
    };
    Connector::new(ConnectorOptions {
        trust,
        identity: Some(identity),
    })
    .map_err(|error| ProxyError::ClientIdentity {
        cert_file: cert_file.clone(),
        key_file: key_file.clone(),
        reason: error.to_string(),
    })
}

/// The content of `file`, the value of `setting`.
fn read(file: &Path, setting: &'static str) -> Result<Vec<u8>, ProxyError> {
    std::fs::read(file).map_err(|error| ProxyError::UpstreamTls {
        setting,
        file: file.to_path_buf(),
        reason: error.to_string(),
    })
}

#[cfg(test)]
#[path = "state_test.rs"]
mod tests;
