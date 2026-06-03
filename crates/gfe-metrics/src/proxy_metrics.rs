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

/// Labels for the request-latency histogram (no `status`, to keep histogram
/// series — buckets × label-combos — bounded).
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RequestDurationLabels {
    pub listener: String,
    pub host: String,
    pub route: String,
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
    pub connections_rejected: Family<RejectLabel, Counter>,
    pub tls_handshakes: Family<TlsResultLabel, Counter>,
    pub tls_handshake_duration_seconds: Histogram,
    pub tls_sni_no_cert: Counter,
    pub requests: Family<RequestLabels, Counter>,
    pub request_duration_seconds: Family<RequestDurationLabels, Histogram>,
    pub no_route: Counter,
    pub no_healthy_upstream: Counter,
    pub upstream_requests: Family<UpstreamLabels, Counter>,
    pub upstream_request_duration_seconds: Family<UpstreamDurationLabels, Histogram>,
    pub upstream_connect_errors: Counter,
    pub bytes_in: Counter,
    pub bytes_out: Counter,
}

fn latency_buckets() -> [f64; 11] {
    // Seconds: 1ms .. 30s, exponential-ish.
    [
        0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 30.0,
    ]
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
            connections_rejected: Family::default(),
            tls_handshakes: Family::default(),
            tls_handshake_duration_seconds: Histogram::new(latency_buckets()),
            tls_sni_no_cert: Counter::default(),
            requests: Family::default(),
            request_duration_seconds: Family::new_with_constructor(latency_histogram),
            no_route: Counter::default(),
            no_healthy_upstream: Counter::default(),
            upstream_requests: Family::default(),
            upstream_request_duration_seconds: Family::new_with_constructor(latency_histogram),
            upstream_connect_errors: Counter::default(),
            bytes_in: Counter::default(),
            bytes_out: Counter::default(),
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
            "gfe_connections_rejected",
            "Connections rejected (limit, handshake_timeout)",
            m.connections_rejected.clone(),
        );
        registry.register(
            "gfe_tls_handshakes",
            "TLS handshakes by result",
            m.tls_handshakes.clone(),
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
            "Requests by route and status",
            m.requests.clone(),
        );
        registry.register(
            "gfe_request_duration_seconds",
            "End-to-end request latency",
            m.request_duration_seconds.clone(),
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
            "Client-side bytes received",
            m.bytes_in.clone(),
        );
        registry.register(
            "gfe_bytes_out",
            "Client-side bytes sent",
            m.bytes_out.clone(),
        );

        m
    }
}
