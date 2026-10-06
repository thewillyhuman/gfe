use super::*;
use gfe_config::{LbPolicy, PoolId, ProbeType, Upstream};

fn pool(id: &str, scheme: Scheme, health_check: Option<HealthCheckConfig>) -> UpstreamPool {
    UpstreamPool {
        id: PoolId(id.into()),
        scheme,
        lb_policy: LbPolicy::RoundRobin,
        upstreams: vec![Upstream {
            host: "10.0.0.1".into(),
            port: 8080,
            weight: 1,
        }],
        health_check,
        max_in_flight: None,
    }
}

fn of_type(probe_type: ProbeType) -> HealthCheckConfig {
    HealthCheckConfig {
        probe_type,
        ..HealthCheckConfig::default()
    }
}

/// The exported value of `metric` for backend `10.0.0.1:8080` under `pool`.
fn series(metrics: &GfeMetrics, metric: &str, pool: &str) -> Option<i64> {
    let prefix = format!(r#"{metric}{{pool="{pool}",backend="10.0.0.1:8080"}} "#);
    metrics
        .encode()
        .lines()
        .find_map(|line| line.strip_prefix(&prefix)?.parse().ok())
}

// --- the checks of the config ---------------------------------------------

#[test]
fn checks_every_backend_of_a_pool_with_its_own_check() {
    let check = HealthCheckConfig {
        interval: Duration::from_millis(250),
        timeout: Duration::from_millis(100),
        healthy_threshold: 4,
        unhealthy_threshold: 5,
        path: "/ready".into(),
        expected_status: 204,
        drain_status: Some(503),
        probe_type: ProbeType::Http,
    };

    let pools = checked_pools(
        &[pool("p", Scheme::Http, Some(check))],
        &of_type(ProbeType::Tcp),
    );

    assert_eq!(
        pools,
        vec![CheckedPool {
            id: "p".into(),
            check: CheckSpec {
                probe: ProbeKind::Http {
                    path: "/ready".into(),
                    expected_status: 204,
                    drain_status: Some(503),
                    tls: false,
                },
                interval: Duration::from_millis(250),
                timeout: Duration::from_millis(100),
                healthy_threshold: 4,
                unhealthy_threshold: 5,
            },
            backends: vec![("10.0.0.1".into(), 8080)],
        }]
    );
}

#[test]
fn a_pool_without_a_check_gets_the_node_defaults() {
    let pools = checked_pools(&[pool("p", Scheme::Http, None)], &of_type(ProbeType::Tcp));

    assert_eq!(pools[0].check.probe, ProbeKind::Tcp);
}

/// `http` is the node default, so it is what an `https` pool without its
/// own check gets: probing its TLS port in cleartext would fail every
/// backend.
#[test]
fn an_http_probe_uses_tls_for_an_https_pool() {
    let pools = checked_pools(
        &[pool("p", Scheme::Https, None)],
        &HealthCheckConfig::default(),
    );

    assert!(matches!(
        pools[0].check.probe,
        ProbeKind::Http { tls: true, .. }
    ));
}

#[test]
fn an_http_probe_stays_cleartext_for_a_cleartext_pool() {
    for scheme in [Scheme::Http, Scheme::H2c] {
        let pools = checked_pools(&[pool("p", scheme, None)], &HealthCheckConfig::default());

        assert!(matches!(
            pools[0].check.probe,
            ProbeKind::Http { tls: false, .. }
        ));
    }
}

#[test]
fn an_https_probe_uses_tls_whatever_the_scheme() {
    for scheme in [Scheme::Http, Scheme::Https, Scheme::H2c] {
        let pools = checked_pools(
            &[pool("p", scheme, Some(of_type(ProbeType::Https)))],
            &HealthCheckConfig::default(),
        );

        assert!(matches!(
            pools[0].check.probe,
            ProbeKind::Http { tls: true, .. }
        ));
    }
}

/// A gRPC server is reached the way the pool's traffic reaches it.
#[test]
fn a_grpc_probe_uses_tls_for_an_https_pool_only() {
    let probe = |scheme| {
        checked_pools(
            &[pool("p", scheme, Some(of_type(ProbeType::Grpc)))],
            &HealthCheckConfig::default(),
        )[0]
        .check
        .probe
        .clone()
    };

    assert_eq!(probe(Scheme::Https), ProbeKind::Grpc { tls: true });
    assert_eq!(probe(Scheme::H2c), ProbeKind::Grpc { tls: false });
}

// --- the metrics ----------------------------------------------------------

#[test]
fn a_healthy_backend_exports_healthy_and_not_draining() {
    let metrics = Arc::new(GfeMetrics::new());
    let observer = HealthMetrics::new(Arc::clone(&metrics));

    observer.status_changed("p", "10.0.0.1", 8080, HealthStatus::Healthy);

    assert_eq!(series(&metrics, "gfe_backend_health_status", "p"), Some(1));
    assert_eq!(series(&metrics, "gfe_backend_draining", "p"), Some(0));
}

#[test]
fn a_draining_backend_exports_draining_and_not_healthy() {
    let metrics = Arc::new(GfeMetrics::new());
    let observer = HealthMetrics::new(Arc::clone(&metrics));

    observer.status_changed("p", "10.0.0.1", 8080, HealthStatus::Draining);

    assert_eq!(series(&metrics, "gfe_backend_health_status", "p"), Some(0));
    assert_eq!(series(&metrics, "gfe_backend_draining", "p"), Some(1));
}

#[test]
fn an_unhealthy_backend_exports_neither() {
    let metrics = Arc::new(GfeMetrics::new());
    let observer = HealthMetrics::new(Arc::clone(&metrics));

    observer.status_changed("p", "10.0.0.1", 8080, HealthStatus::Unhealthy);

    assert_eq!(series(&metrics, "gfe_backend_health_status", "p"), Some(0));
    assert_eq!(series(&metrics, "gfe_backend_draining", "p"), Some(0));
}

#[test]
fn a_backend_that_left_a_pool_stops_being_exported_under_it() {
    let metrics = Arc::new(GfeMetrics::new());
    let observer = HealthMetrics::new(Arc::clone(&metrics));
    observer.status_changed("p", "10.0.0.1", 8080, HealthStatus::Healthy);
    observer.status_changed("q", "10.0.0.1", 8080, HealthStatus::Healthy);

    observer.backend_left("p", "10.0.0.1", 8080);

    assert_eq!(series(&metrics, "gfe_backend_health_status", "p"), None);
    assert_eq!(series(&metrics, "gfe_backend_draining", "p"), None);
    assert_eq!(series(&metrics, "gfe_backend_health_status", "q"), Some(1));
}

#[test]
fn times_every_probe() {
    let metrics = Arc::new(GfeMetrics::new());
    let observer = HealthMetrics::new(Arc::clone(&metrics));

    observer.probe_finished(Duration::from_millis(3));

    assert!(
        metrics
            .encode()
            .lines()
            .any(|line| line == "gfe_health_check_duration_seconds_count 1"),
        "{}",
        metrics.encode()
    );
}
