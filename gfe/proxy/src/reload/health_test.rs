use super::*;
use gfe_config::{LbPolicy, PoolId, ProbeType, Upstream};
use std::time::Duration;

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
