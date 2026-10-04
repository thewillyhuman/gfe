//! Serving connections: the listening sockets and their accept loops, the
//! TLS handshake, HTTP/1 and HTTP/2 over what was accepted, the client-side
//! timeouts and limits, and draining.
//!
//! What a request is answered with is not decided here: every request is
//! handed to a [`RequestHandler`], with what is known about the connection
//! it arrived on ([`ConnInfo`]).

pub mod acceptor;
pub mod activity;
pub mod conn_record;
pub mod connection;
pub mod drain;
pub mod listeners;

pub use conn_record::TlsInfo;
pub use drain::DrainController;
pub use listeners::ListenerSet;

use crate::config::{LimitsConfig, ListenerId, TimeoutsConfig};
use crate::upstream::BoxError;
use bytes::Bytes;
use gfe_observability::GfeMetrics;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::{Request, Response};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

/// The unified response body type a node returns to clients.
pub type RespBody = BoxBody<Bytes, BoxError>;

/// What every connection a node serves shares.
pub struct ServerShared {
    /// Metrics.
    pub metrics: Arc<GfeMetrics>,
    pub limits: LimitsConfig,
    pub timeouts: TimeoutsConfig,
    /// Set when the node is draining (fails `/readyz`).
    pub draining: AtomicBool,
    /// The kernel's view of the accept queue, where one is available.
    pub accept_queue: Option<Arc<dyn AcceptQueue>>,
}

impl ServerShared {
    pub fn new(metrics: Arc<GfeMetrics>, limits: LimitsConfig, timeouts: TimeoutsConfig) -> Self {
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
        ServerShared {
            metrics,
            limits,
            timeouts,
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

/// What only the kernel knows about a connection the node has just accepted.
/// Serving does not care where the answer comes from; the node provides an
/// implementation when it has one (eBPF) and none otherwise.
pub trait AcceptQueue: Send + Sync {
    /// How long the connection between `local` and `peer` had been waiting,
    /// its handshake complete, when `accept` returned it. `None` if unknown.
    fn waited(&self, local: SocketAddr, peer: SocketAddr) -> Option<Duration>;
}

/// What is known about the connection a request arrived on.
#[derive(Clone)]
pub struct ConnInfo {
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

/// Whoever answers the requests of the connections a node serves.
pub trait RequestHandler: Send + Sync + 'static {
    /// Answer `req`, which arrived on the connection `conn` describes.
    fn handle(
        self: &Arc<Self>,
        conn: ConnInfo,
        req: Request<Incoming>,
    ) -> impl Future<Output = Response<RespBody>> + Send;
}

/// A duration in milliseconds, with microsecond resolution.
pub fn millis(duration: Duration) -> f64 {
    duration.as_micros() as f64 / 1000.0
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

        ServerShared::new(metrics.clone(), limits, TimeoutsConfig::default());

        let exposed = metrics.encode();
        assert!(exposed.contains("gfe_connections_limit 7"), "{exposed}");
        assert!(
            exposed.contains("gfe_listener_connections_limit 3"),
            "{exposed}"
        );
    }
}
