//! Data-plane metrics: what happens to client connections, TLS handshakes,
//! requests, and the requests sent on to backends.
//!
//! Every label value is bounded by the config (listener, vhost pattern,
//! route, pool, backend) or by a fixed set (status, reason, kind), so that
//! no client can make the number of series grow.

use netkit_observability::prometheus_client;
use netkit_observability::{Counter, EncodeLabelSet, Family, Gauge, Histogram, Registry};

/// `listener` label for per-listener connection metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ListenerLabel {
    pub listener: String,
}

/// `reason` label for rejected connections.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RejectLabel {
    pub reason: String,
}

/// Labels for closed connections. `reason` is why the connection ended.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct CloseLabels {
    pub listener: String,
    pub reason: String,
}

/// The parameters a TLS handshake settled on.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TlsLabels {
    pub version: String,
    pub cipher: String,
    pub alpn: String,
    pub resumed: String,
}

/// `reason` label for failed TLS handshakes.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TlsFailureLabel {
    pub reason: String,
}

/// `result` label for TLS handshakes.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TlsResultLabel {
    pub result: String,
}

/// Labels for completed requests. `vhost` is the matched route's configured
/// host *pattern* (bounded by config), never the raw client `Host` header.
/// It is not called `host`: monitoring systems commonly put the machine a
/// series comes from under that name, and the two would collide.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RequestLabels {
    pub listener: String,
    pub vhost: String,
    pub route: String,
    pub status: String,
}

/// Labels for per-route request metrics that do not split by `status` (the
/// latency histogram, to keep its series — buckets × label-combos — bounded).
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RouteLabels {
    pub listener: String,
    pub vhost: String,
    pub route: String,
}

/// Labels for requests that did not run to completion. `by` is who broke the
/// exchange off: `client` or `upstream`.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct AbortLabels {
    pub listener: String,
    pub vhost: String,
    pub route: String,
    pub by: String,
}

/// Labels for finished gRPC calls. `grpc_status` is the numeric status code
/// the call ended with (0 is OK), bounded to the codes gRPC defines.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct GrpcLabels {
    pub listener: String,
    pub vhost: String,
    pub route: String,
    pub grpc_status: String,
}

/// Labels for upstream requests.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct UpstreamLabels {
    pub pool: String,
    pub backend: String,
    pub status: String,
}

/// Labels for upstream requests that failed before any response. `kind` is
/// what went wrong (connect_timeout, connect_refused, connect_error, tls,
/// reset, connection_limit, timeout, other).
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct UpstreamErrorLabels {
    pub pool: String,
    pub backend: String,
    pub kind: String,
}

/// `pool` label for per-pool upstream metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PoolLabel {
    pub pool: String,
}

/// Labels for the upstream-latency histogram (per pool and backend).
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct UpstreamDurationLabels {
    pub pool: String,
    pub backend: String,
}

/// Data-plane (proxy) metrics.
#[derive(Clone)]
pub struct ProxyMetrics {
    pub connections_accepted: Family<ListenerLabel, Counter>,
    pub connections_active: Gauge,
    pub listener_connections_active: Family<ListenerLabel, Gauge>,
    pub connections_limit: Gauge,
    pub listener_connections_limit: Gauge,
    pub connections_rejected: Family<RejectLabel, Counter>,
    pub client_rate_untracked: Gauge,
    pub connections_closed: Family<CloseLabels, Counter>,
    pub connection_duration_seconds: Family<ListenerLabel, Histogram>,
    pub accept_queue_wait_seconds: Family<ListenerLabel, Histogram>,
    pub tls_handshakes: Family<TlsResultLabel, Counter>,
    pub tls_handshake_failures: Family<TlsFailureLabel, Counter>,
    pub tls_connections: Family<TlsLabels, Counter>,
    pub tls_handshake_duration_seconds: Histogram,
    pub tls_sni_no_cert: Counter,
    pub requests: Family<RequestLabels, Counter>,
    pub requests_in_flight: Gauge,
    pub requests_aborted: Family<AbortLabels, Counter>,
    pub request_duration_seconds: Family<RouteLabels, Histogram>,
    pub request_body_bytes: Family<RouteLabels, Counter>,
    pub response_body_bytes: Family<RouteLabels, Counter>,
    pub grpc_responses: Family<GrpcLabels, Counter>,
    pub no_route: Counter,
    pub no_healthy_upstream: Counter,
    pub upstream_requests: Family<UpstreamLabels, Counter>,
    pub upstream_request_duration_seconds: Family<UpstreamDurationLabels, Histogram>,
    pub upstream_connect_errors: Counter,
    pub upstream_errors: Family<UpstreamErrorLabels, Counter>,
    pub upstream_retries: Family<PoolLabel, Counter>,
    pub upstream_pool_full: Family<PoolLabel, Counter>,
    pub upstream_pool_rate_limited: Family<PoolLabel, Counter>,
    pub upstream_requests_in_flight: Family<UpstreamDurationLabels, Gauge>,
    pub upstream_connections: Gauge,
    pub upstream_connections_limit: Gauge,
    pub bytes_in: Family<ListenerLabel, Counter>,
    pub bytes_out: Family<ListenerLabel, Counter>,
}

fn latency_buckets() -> [f64; 11] {
    // Seconds: 1ms .. 30s, exponential-ish.
    [
        0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 30.0,
    ]
}

/// Constructor for connection-lifetime histograms in a `Family`. Seconds:
/// 10ms .. 1h, as connections live anywhere from one request to hours.
fn lifetime_histogram() -> Histogram {
    Histogram::new([0.01, 0.1, 0.5, 1.0, 5.0, 15.0, 60.0, 300.0, 900.0, 3600.0])
}

/// Constructor for accept-queue wait histograms in a `Family`. Seconds:
/// 50µs .. 1s. A node that keeps up accepts within microseconds; the upper
/// buckets are where falling behind shows.
fn queue_wait_histogram() -> Histogram {
    Histogram::new([
        0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0,
    ])
}

/// Constructor for latency histograms in a `Family`. A plain `fn` (not a
/// closure) so the `Family`'s default constructor type parameter applies.
fn latency_histogram() -> Histogram {
    Histogram::new(latency_buckets())
}

impl ProxyMetrics {
    pub fn register(registry: &mut Registry) -> Self {
        let m = ProxyMetrics {
            connections_accepted: Family::default(),
            connections_active: Gauge::default(),
            listener_connections_active: Family::default(),
            connections_limit: Gauge::default(),
            listener_connections_limit: Gauge::default(),
            connections_rejected: Family::default(),
            client_rate_untracked: Gauge::default(),
            connections_closed: Family::default(),
            connection_duration_seconds: Family::new_with_constructor(lifetime_histogram),
            accept_queue_wait_seconds: Family::new_with_constructor(queue_wait_histogram),
            tls_handshakes: Family::default(),
            tls_handshake_failures: Family::default(),
            tls_connections: Family::default(),
            tls_handshake_duration_seconds: Histogram::new(latency_buckets()),
            tls_sni_no_cert: Counter::default(),
            requests: Family::default(),
            requests_in_flight: Gauge::default(),
            requests_aborted: Family::default(),
            request_duration_seconds: Family::new_with_constructor(latency_histogram),
            request_body_bytes: Family::default(),
            response_body_bytes: Family::default(),
            grpc_responses: Family::default(),
            no_route: Counter::default(),
            no_healthy_upstream: Counter::default(),
            upstream_requests: Family::default(),
            upstream_request_duration_seconds: Family::new_with_constructor(latency_histogram),
            upstream_connect_errors: Counter::default(),
            upstream_errors: Family::default(),
            upstream_retries: Family::default(),
            upstream_pool_full: Family::default(),
            upstream_pool_rate_limited: Family::default(),
            upstream_requests_in_flight: Family::default(),
            upstream_connections: Gauge::default(),
            upstream_connections_limit: Gauge::default(),
            bytes_in: Family::default(),
            bytes_out: Family::default(),
        };

        registry.register(
            "gfe_connections_accepted",
            "Client connections accepted",
            m.connections_accepted.clone(),
        );
        registry.register(
            "gfe_connections_active",
            "Currently open client connections",
            m.connections_active.clone(),
        );
        registry.register(
            "gfe_listener_connections_active",
            "Currently open client connections per listener",
            m.listener_connections_active.clone(),
        );
        registry.register(
            "gfe_connections_limit",
            "Configured limit on open client connections (max_connections)",
            m.connections_limit.clone(),
        );
        registry.register(
            "gfe_listener_connections_limit",
            "Configured limit on open client connections per listener (max_connections_listener)",
            m.listener_connections_limit.clone(),
        );
        registry.register(
            "gfe_connections_rejected",
            "Connections closed at accept, by reason: a connection limit (limit), the client's connection rate (client_rate), a TLS handshake that did not finish in time (handshake_timeout)",
            m.connections_rejected.clone(),
        );
        registry.register(
            "gfe_client_rate_untracked",
            "Connections served without counting against their client's connection rate, because the node already followed as many clients as it can",
            m.client_rate_untracked.clone(),
        );
        registry.register(
            "gfe_connections_closed",
            "Closed client connections by reason",
            m.connections_closed.clone(),
        );
        registry.register(
            "gfe_connection_duration_seconds",
            "Lifetime of client connections",
            m.connection_duration_seconds.clone(),
        );
        registry.register(
            "gfe_accept_queue_wait_seconds",
            "Time connections spent established but not yet accepted (needs the eBPF view)",
            m.accept_queue_wait_seconds.clone(),
        );
        registry.register(
            "gfe_tls_handshakes",
            "TLS handshakes by result",
            m.tls_handshakes.clone(),
        );
        registry.register(
            "gfe_tls_handshake_failures",
            "Failed TLS handshakes by reason",
            m.tls_handshake_failures.clone(),
        );
        registry.register(
            "gfe_tls_connections",
            "TLS connections established, by negotiated parameters",
            m.tls_connections.clone(),
        );
        registry.register(
            "gfe_tls_handshake_duration_seconds",
            "TLS handshake latency",
            m.tls_handshake_duration_seconds.clone(),
        );
        registry.register(
            "gfe_tls_sni_no_cert",
            "Handshakes with no matching certificate",
            m.tls_sni_no_cert.clone(),
        );
        registry.register(
            "gfe_requests",
            "Finished requests by route and status (499: abandoned by the client before a response)",
            m.requests.clone(),
        );
        registry.register(
            "gfe_requests_in_flight",
            "Requests received whose response is not finished yet",
            m.requests_in_flight.clone(),
        );
        registry.register(
            "gfe_requests_aborted",
            "Requests broken off before completion, by who did it (client, upstream)",
            m.requests_aborted.clone(),
        );
        registry.register(
            "gfe_request_duration_seconds",
            "Time from request head to the last byte of the response",
            m.request_duration_seconds.clone(),
        );
        registry.register(
            "gfe_request_body_bytes",
            "Request body bytes received from clients",
            m.request_body_bytes.clone(),
        );
        registry.register(
            "gfe_response_body_bytes",
            "Response body bytes sent to clients",
            m.response_body_bytes.clone(),
        );
        registry.register(
            "gfe_grpc_responses",
            "Finished gRPC calls by gRPC status code (0 is OK)",
            m.grpc_responses.clone(),
        );
        registry.register(
            "gfe_no_route",
            "Requests matching no route",
            m.no_route.clone(),
        );
        registry.register(
            "gfe_no_healthy_upstream",
            "Requests with no healthy upstream",
            m.no_healthy_upstream.clone(),
        );
        registry.register(
            "gfe_upstream_requests",
            "Upstream requests by pool/backend/status",
            m.upstream_requests.clone(),
        );
        registry.register(
            "gfe_upstream_request_duration_seconds",
            "Upstream round-trip latency",
            m.upstream_request_duration_seconds.clone(),
        );
        registry.register(
            "gfe_upstream_connect_errors",
            "Upstream requests that failed before any response (all kinds)",
            m.upstream_connect_errors.clone(),
        );
        registry.register(
            "gfe_upstream_errors",
            "Upstream requests that failed before any response, by kind",
            m.upstream_errors.clone(),
        );
        registry.register(
            "gfe_upstream_retries",
            "Requests retried against another backend selection",
            m.upstream_retries.clone(),
        );
        registry.register(
            "gfe_upstream_pool_full",
            "Requests refused because their pool had max_in_flight requests in flight",
            m.upstream_pool_full.clone(),
        );
        registry.register(
            "gfe_upstream_pool_rate_limited",
            "Requests refused because their pool had admitted max_requests_per_second requests within the last second",
            m.upstream_pool_rate_limited.clone(),
        );
        registry.register(
            "gfe_upstream_requests_in_flight",
            "Requests a backend is currently working on, until the response ends",
            m.upstream_requests_in_flight.clone(),
        );
        registry.register(
            "gfe_upstream_connections",
            "Upstream connections open, over all backends",
            m.upstream_connections.clone(),
        );
        registry.register(
            "gfe_upstream_connections_limit",
            "Configured limit on open upstream connections (max_upstream_connections)",
            m.upstream_connections_limit.clone(),
        );
        registry.register(
            "gfe_bytes_in",
            "Bytes read from client sockets (on the wire, TLS included)",
            m.bytes_in.clone(),
        );
        registry.register(
            "gfe_bytes_out",
            "Bytes written to client sockets (on the wire, TLS included)",
            m.bytes_out.clone(),
        );

        m
    }
}

#[cfg(test)]
#[path = "proxy_test.rs"]
mod tests;
