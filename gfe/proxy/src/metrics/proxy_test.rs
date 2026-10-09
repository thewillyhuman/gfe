use super::*;

fn exposition() -> String {
    let mut registry = Registry::default();
    ProxyMetrics::register(&mut registry);
    netkit_observability::encode(&registry)
}

#[test]
fn exposes_every_proxy_metric_with_its_type() {
    let text = exposition();

    for (name, kind) in [
        ("gfe_connections_accepted", "counter"),
        ("gfe_connections_active", "gauge"),
        ("gfe_listener_connections_active", "gauge"),
        ("gfe_connections_limit", "gauge"),
        ("gfe_listener_connections_limit", "gauge"),
        ("gfe_connections_rejected", "counter"),
        ("gfe_client_rate_untracked", "gauge"),
        ("gfe_connections_closed", "counter"),
        ("gfe_connection_duration_seconds", "histogram"),
        ("gfe_accept_queue_wait_seconds", "histogram"),
        ("gfe_tls_handshakes", "counter"),
        ("gfe_tls_handshake_failures", "counter"),
        ("gfe_tls_connections", "counter"),
        ("gfe_tls_handshake_duration_seconds", "histogram"),
        ("gfe_tls_sni_no_cert", "counter"),
        ("gfe_requests", "counter"),
        ("gfe_requests_in_flight", "gauge"),
        ("gfe_requests_aborted", "counter"),
        ("gfe_request_duration_seconds", "histogram"),
        ("gfe_request_body_bytes", "counter"),
        ("gfe_response_body_bytes", "counter"),
        ("gfe_grpc_responses", "counter"),
        ("gfe_no_route", "counter"),
        ("gfe_no_healthy_upstream", "counter"),
        ("gfe_upstream_requests", "counter"),
        ("gfe_upstream_request_duration_seconds", "histogram"),
        ("gfe_upstream_connect_errors", "counter"),
        ("gfe_upstream_errors", "counter"),
        ("gfe_upstream_retries", "counter"),
        ("gfe_upstream_pool_full", "counter"),
        ("gfe_upstream_requests_in_flight", "gauge"),
        ("gfe_upstream_connections", "gauge"),
        ("gfe_upstream_connections_limit", "gauge"),
        ("gfe_bytes_in", "counter"),
        ("gfe_bytes_out", "counter"),
    ] {
        assert!(
            text.contains(&format!("# TYPE {name} {kind}\n")),
            "{name} {kind} missing from:\n{text}"
        );
    }
}

#[test]
fn request_series_are_labelled_with_vhost_not_host() {
    let mut registry = Registry::default();
    let metrics = ProxyMetrics::register(&mut registry);
    metrics
        .requests
        .get_or_create(&RequestLabels {
            listener: "https".into(),
            vhost: "*.example.org".into(),
            route: "api".into(),
            status: "200".into(),
        })
        .inc();
    let text = netkit_observability::encode(&registry);

    assert!(
        text.contains(
            "gfe_requests_total{listener=\"https\",vhost=\"*.example.org\",route=\"api\",status=\"200\"} 1"
        ),
        "{text}"
    );
}

#[test]
fn request_latency_has_the_documented_buckets() {
    let mut registry = Registry::default();
    let metrics = ProxyMetrics::register(&mut registry);
    metrics
        .request_duration_seconds
        .get_or_create(&RouteLabels {
            listener: "https".into(),
            vhost: "example.org".into(),
            route: "api".into(),
        })
        .observe(0.002);
    let text = netkit_observability::encode(&registry);

    let buckets: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("gfe_request_duration_seconds_bucket"))
        .filter_map(|line| line.split("le=\"").nth(1)?.split('"').next())
        .collect();
    assert_eq!(
        buckets,
        [
            "0.001", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1.0", "5.0", "30.0",
            "+Inf"
        ]
    );
}
