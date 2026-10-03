use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;

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

/// Labels for completed requests. `host` is the matched route's configured
/// host *pattern* (bounded by config), never the raw client `Host` header.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RequestLabels {
    pub listener: String,
    pub host: String,
    pub route: String,
    pub status: String,
}

/// Labels for per-route request metrics that do not split by `status` (the
/// latency histogram, to keep its series — buckets × label-combos — bounded).
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RouteLabels {
    pub listener: String,
    pub host: String,
    pub route: String,
}

/// Labels for requests that did not run to completion. `by` is who broke the
/// exchange off: `client` or `upstream`.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct AbortLabels {
    pub listener: String,
    pub host: String,
    pub route: String,
    pub by: String,
}

/// Labels for finished gRPC calls. `grpc_status` is the numeric status code
/// the call ended with (0 is OK), bounded to the codes gRPC defines.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct GrpcLabels {
    pub listener: String,
    pub host: String,
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
    pub connections_rejected: Family<RejectLabel, Counter>,
    pub connections_closed: Family<CloseLabels, Counter>,
    pub connection_duration_seconds: Family<ListenerLabel, Histogram>,
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
            connections_rejected: Family::default(),
            connections_closed: Family::default(),
            connection_duration_seconds: Family::new_with_constructor(lifetime_histogram),
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
            "gfe_connections_rejected",
            "Connections refused at accept because a connection limit was reached",
            m.connections_rejected.clone(),
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
            "Failures opening an upstream connection",
            m.upstream_connect_errors.clone(),
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
