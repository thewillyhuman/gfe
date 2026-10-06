//! Per-request accounting: everything GFE knows about one request, reported
//! exactly once, as metrics and as an access-log event, when the exchange is
//! over.
//!
//! "Over" means the response was written to its last byte, or the exchange
//! was abandoned. Pingora calls `logging` at the end of every request it
//! read the head of, whatever happened to it; the context reports there,
//! and, should the task serving the request be cancelled before (a
//! connection cut at the end of a drain), when it is dropped (see
//! `context`).

use crate::metrics::{AbortLabels, GrpcLabels, ProxyMetrics, RequestLabels, RouteLabels};
use crate::routing::CompiledRoute;
use http::{HeaderMap, Method, Version};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Logged as the status of a request the client abandoned before GFE had a
/// response for it. Not a real HTTP status: the convention nginx established.
pub(crate) const CLIENT_CLOSED_REQUEST: u16 = 499;

/// The highest status code gRPC defines (`UNAUTHENTICATED`). Anything above
/// it is not reported, which keeps the metric label bounded.
const MAX_GRPC_STATUS: u8 = 16;

/// Label value for requests that matched no route.
const NO_ROUTE: &str = "none";

/// The `grpc-status` in a set of response headers or trailers, if valid.
pub(crate) fn grpc_status(headers: &HeaderMap) -> Option<u8> {
    let status: u8 = headers.get("grpc-status")?.to_str().ok()?.parse().ok()?;
    (status <= MAX_GRPC_STATUS).then_some(status)
}

/// How an exchange ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Termination {
    /// The response was written to the end.
    Complete,
    /// The client went away first: before the response, or in the middle
    /// of it.
    ClientAbort,
    /// The upstream failed in the middle of the response body.
    UpstreamAbort,
}

impl Termination {
    /// How an exchange ended, from how the engine says it ended (`failed`:
    /// with an error, and whether that error was the client's side), whether
    /// GFE answered the request itself, and whether a response had started.
    pub(crate) fn of(failed: Option<Side>, answered: bool, response_started: bool) -> Termination {
        match failed {
            None => Termination::Complete,
            Some(_) if answered => Termination::Complete,
            Some(Side::Client) => Termination::ClientAbort,
            // Nothing reached the client: it was not there to answer.
            Some(Side::Upstream) if !response_started => Termination::ClientAbort,
            Some(Side::Upstream) => Termination::UpstreamAbort,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Termination::Complete => "complete",
            Termination::ClientAbort => "client_abort",
            Termination::UpstreamAbort => "upstream_abort",
        }
    }

    /// The `by` label of `gfe_requests_aborted_total`, if it was aborted.
    fn aborted_by(self) -> Option<&'static str> {
        match self {
            Termination::Complete => None,
            Termination::ClientAbort => Some("client"),
            Termination::UpstreamAbort => Some("upstream"),
        }
    }
}

/// Which side an error that ended an exchange came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    /// The client's connection.
    Client,
    /// The backend, or GFE itself.
    Upstream,
}

/// What a request's connection says about it.
#[derive(Debug, Clone)]
pub(crate) struct Arrival {
    /// The client's address, if known.
    pub(crate) client: Option<SocketAddr>,
    /// The id of the listener it arrived on, as configured when it did.
    pub(crate) listener: String,
    pub(crate) is_tls: bool,
    pub(crate) sni: Option<String>,
    pub(crate) tls_version: Option<&'static str>,
    pub(crate) tls_cipher: Option<String>,
}

/// The upstream leg of a forwarded request.
#[derive(Debug)]
pub(crate) struct UpstreamLeg {
    pub(crate) pool: String,
    /// The backend of the last attempt, if one was selected.
    pub(crate) backend: Option<String>,
    pub(crate) attempts: u32,
    /// Time from the first attempt until response headers arrived.
    pub(crate) time_to_first_byte: Option<Duration>,
}

/// One request, from its parsed head to the end of its exchange.
#[derive(Debug)]
pub(crate) struct RequestRecord {
    pub(crate) started: Instant,
    pub(crate) request_id: String,
    pub(crate) arrival: Arrival,
    method: Method,
    http_version: Version,
    /// The host the request is for, as used for routing.
    pub(crate) host: String,
    path: String,
    user_agent: Option<String>,
    pub(crate) is_grpc: bool,
    /// The route it matched.
    pub(crate) route: Option<Arc<CompiledRoute>>,
    pub(crate) upstream: Option<UpstreamLeg>,
    /// The status of the response; `None` while there is none.
    pub(crate) status: Option<u16>,
    /// Why GFE answered the request itself instead of relaying a response.
    pub(crate) error: Option<&'static str>,
    /// The status a gRPC call ended with. It arrives in the trailers, or in
    /// the headers when the call fails before sending any message.
    pub(crate) grpc_status: Option<u8>,
    pub(crate) request_bytes: u64,
    pub(crate) response_bytes: u64,
    pub(crate) termination: Termination,
}

impl RequestRecord {
    /// Start accounting for a request, received at `started`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin(
        started: Instant,
        arrival: Arrival,
        request_id: String,
        method: Method,
        http_version: Version,
        path: String,
        user_agent: Option<String>,
        is_grpc: bool,
    ) -> Self {
        RequestRecord {
            started,
            request_id,
            arrival,
            method,
            http_version,
            host: String::new(),
            path,
            user_agent,
            is_grpc,
            route: None,
            upstream: None,
            status: None,
            error: None,
            grpc_status: None,
            request_bytes: 0,
            response_bytes: 0,
            // Until the end says otherwise, the only way the record can end
            // is the client abandoning the request.
            termination: Termination::ClientAbort,
        }
    }

    /// Report the request: the single place a request is counted and
    /// logged. The caller makes sure it is called once.
    pub(crate) fn report(&self, metrics: &ProxyMetrics) {
        let elapsed = self.started.elapsed();
        let status = self.status.unwrap_or(CLIENT_CLOSED_REQUEST);
        let (route, vhost) = match &self.route {
            Some(route) => (route.id.0.as_str(), route.host.as_str()),
            None => (NO_ROUTE, NO_ROUTE),
        };
        let per_route = RouteLabels {
            listener: self.arrival.listener.clone(),
            vhost: vhost.to_string(),
            route: route.to_string(),
        };

        metrics.requests_in_flight.dec();
        metrics
            .requests
            .get_or_create(&RequestLabels {
                listener: per_route.listener.clone(),
                vhost: per_route.vhost.clone(),
                route: per_route.route.clone(),
                status: status.to_string(),
            })
            .inc();
        metrics
            .request_duration_seconds
            .get_or_create(&per_route)
            .observe(elapsed.as_secs_f64());
        metrics
            .request_body_bytes
            .get_or_create(&per_route)
            .inc_by(self.request_bytes);
        metrics
            .response_body_bytes
            .get_or_create(&per_route)
            .inc_by(self.response_bytes);
        if let Some(grpc_status) = self.grpc_status {
            metrics
                .grpc_responses
                .get_or_create(&GrpcLabels {
                    listener: per_route.listener.clone(),
                    vhost: per_route.vhost.clone(),
                    route: per_route.route.clone(),
                    grpc_status: grpc_status.to_string(),
                })
                .inc();
        }
        if let Some(by) = self.termination.aborted_by() {
            metrics
                .requests_aborted
                .get_or_create(&AbortLabels {
                    listener: per_route.listener.clone(),
                    vhost: per_route.vhost.clone(),
                    route: per_route.route.clone(),
                    by: by.to_string(),
                })
                .inc();
        }

        // One structured event per request, under a distinct target so
        // operators can route or sample it independently.
        let upstream = self.upstream.as_ref();
        let arrival = &self.arrival;
        tracing::info!(
            target: "gfe::access",
            request_id = %self.request_id,
            client = arrival.client.map(|client| tracing::field::display(client.ip())),
            client_port = arrival.client.map(|client| client.port()),
            listener = %arrival.listener,
            proto = if arrival.is_tls { "https" } else { "http" },
            http_version = ?self.http_version,
            sni = arrival.sni.as_deref(),
            tls_version = arrival.tls_version,
            tls_cipher = arrival.tls_cipher.as_deref(),
            method = %self.method,
            host = %self.host,
            path = %self.path,
            user_agent = self.user_agent.as_deref(),
            status,
            grpc_status = self.grpc_status,
            route = %route,
            pool = upstream.map(|u| u.pool.as_str()),
            backend = upstream.and_then(|u| u.backend.as_deref()),
            attempts = upstream.map(|u| u.attempts),
            error = self.error,
            termination = self.termination.as_str(),
            request_bytes = self.request_bytes,
            response_bytes = self.response_bytes,
            duration_ms = millis(elapsed),
            upstream_ttfb_ms = upstream.and_then(|u| u.time_to_first_byte).map(millis),
            "request"
        );
    }
}

/// A duration in milliseconds, to the microsecond.
pub(crate) fn millis(duration: Duration) -> f64 {
    duration.as_micros() as f64 / 1000.0
}

#[cfg(test)]
#[path = "record_test.rs"]
mod tests;
