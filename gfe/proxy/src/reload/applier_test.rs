use super::*;
use crate::handler::test_support::state;
use crate::reload::test_support::{cert_entry, http_listener};
use gfe_config::{
    CertEntry, ListenerId, PoolId, Route, RouteAction, RouteId, Scheme, Upstream, UpstreamPool,
};
use netkit_health_checking::{HealthMap, HealthStatus};

fn pool(id: &str, backend: (&str, u16)) -> UpstreamPool {
    UpstreamPool {
        id: PoolId(id.into()),
        scheme: Scheme::Http,
        lb_policy: Default::default(),
        upstreams: vec![Upstream {
            host: backend.0.into(),
            port: backend.1,
            weight: 1,
        }],
        health_check: None,
        max_in_flight: None,
    }
}

/// A config with one listener, one route to pool `p` with one backend, and
/// one default certificate.
fn config() -> DynamicConfig {
    DynamicConfig {
        certificates: vec![CertEntry {
            default: true,
            ..cert_entry(&["example.org"])
        }],
        listeners: vec![http_listener("http", 8080)],
        routes: vec![Route {
            id: RouteId("r".into()),
            listener: ListenerId("http".into()),
            host: "example.org".into(),
            path_prefix: "/".into(),
            action: RouteAction::Forward("p".into()),
        }],
        pools: vec![pool("p", ("10.0.0.1", 80))],
    }
}

#[test]
fn install_swaps_routes_pools_and_certificates() {
    let state = state();

    install(&state, prepare(&config(), state.health()).unwrap());

    let routing = state.routing();
    assert_eq!(routing.routes.route_count(), 1);
    assert_eq!(routing.pools.len(), 1);
    assert!(state.resolver().current().resolve(None).is_some());
}

#[test]
fn install_describes_the_config_in_the_metrics() {
    let state = state();

    install(&state, prepare(&config(), state.health()).unwrap());

    let exported = state.metrics().encode();
    for expected in [
        "gfe_active_routes 1\n",
        "gfe_active_pools 1\n",
        "gfe_cert_expiry_timestamp{sni=\"example.org\"}",
    ] {
        assert!(exported.contains(expected), "{expected} in:\n{exported}");
    }
    assert!(
        !exported.contains("gfe_config_last_reload_timestamp 0\n"),
        "{exported}"
    );
}

#[test]
fn install_stops_exporting_the_expiry_of_a_removed_certificate() {
    let state = state();
    let old = DynamicConfig {
        certificates: vec![cert_entry(&["old.example.org"])],
        listeners: vec![http_listener("http", 8080)],
        ..Default::default()
    };
    let new = DynamicConfig {
        certificates: vec![cert_entry(&["new.example.org"])],
        ..old.clone()
    };
    install(&state, prepare(&old, state.health()).unwrap());

    install(&state, prepare(&new, state.health()).unwrap());

    let exported = state.metrics().encode();
    assert!(!exported.contains("old.example.org"), "{exported}");
    assert!(exported.contains("new.example.org"), "{exported}");
}

#[test]
fn install_forgets_the_health_of_backends_no_longer_configured() {
    let state = state();
    install(&state, prepare(&config(), state.health()).unwrap());
    state.health().set("10.0.0.1", 80, HealthStatus::Unhealthy);
    let moved = DynamicConfig {
        pools: vec![pool("p", ("10.0.0.2", 80))],
        ..config()
    };

    install(&state, prepare(&moved, state.health()).unwrap());

    assert_eq!(state.health().get("10.0.0.1", 80), HealthStatus::Unknown);
    assert_eq!(state.health().len(), 1);
}

#[test]
fn prepare_rejects_a_certificate_that_cannot_be_loaded() {
    let config = DynamicConfig {
        certificates: vec![CertEntry {
            sni: vec![],
            default: true,
            cert_file: "/nonexistent/gfe.crt".into(),
            key_file: "/nonexistent/gfe.key".into(),
        }],
        listeners: vec![http_listener("http", 8080)],
        ..Default::default()
    };

    let error = prepare(&config, &HealthMap::new(true)).unwrap_err();

    assert!(
        error.to_string().contains("/nonexistent/gfe.crt"),
        "{error}"
    );
}

#[test]
fn prepare_rejects_an_invalid_config() {
    let config = DynamicConfig {
        routes: vec![Route {
            id: RouteId("r".into()),
            listener: ListenerId("missing".into()),
            host: "example.org".into(),
            path_prefix: "/".into(),
            action: RouteAction::Forward("p".into()),
        }],
        listeners: vec![http_listener("http", 8080)],
        ..Default::default()
    };

    let error = prepare(&config, &HealthMap::new(true)).unwrap_err();

    assert!(error.to_string().contains("missing"), "{error}");
}

#[test]
fn prepare_changes_nothing_that_is_served() {
    let state = state();

    prepare(&config(), state.health()).unwrap();

    assert_eq!(state.routing().routes.route_count(), 0);
    assert!(state.resolver().current().is_empty());
}

#[test]
fn hands_every_certificate_entry_to_the_library_unchanged() {
    let entry = CertEntry {
        sni: vec!["a.example.org".into(), "*.b.example.org".into()],
        default: true,
        cert_file: "/etc/gfe/tls.crt".into(),
        key_file: "/etc/gfe/tls.key".into(),
    };

    let specs = cert_specs(std::slice::from_ref(&entry));

    assert_eq!(
        specs,
        vec![CertSpec {
            sni: entry.sni.clone(),
            default: true,
            cert_file: entry.cert_file.clone(),
            key_file: entry.key_file.clone(),
        }]
    );
}

#[test]
fn hands_every_pool_to_the_library_carrying_its_scheme() {
    let config = UpstreamPool {
        id: PoolId("p".into()),
        scheme: Scheme::H2c,
        lb_policy: LbPolicy::RingHash,
        upstreams: vec![Upstream {
            host: "backend.example".into(),
            port: 8080,
            weight: 3,
        }],
        health_check: None,
        max_in_flight: std::num::NonZeroU32::new(7),
    };

    let specs = pool_specs(std::slice::from_ref(&config));

    assert_eq!(
        specs,
        vec![PoolSpec {
            id: "p".into(),
            policy: Policy::RingHash,
            backends: vec![Backend {
                host: "backend.example".into(),
                port: 8080,
                weight: 3,
            }],
            max_in_flight: config.max_in_flight,
            payload: Scheme::H2c,
        }]
    );
}

#[test]
fn maps_every_load_balancing_policy_to_its_namesake() {
    let policies = [
        (LbPolicy::RoundRobin, Policy::RoundRobin),
        (LbPolicy::LeastRequest, Policy::LeastRequest),
        (LbPolicy::RingHash, Policy::RingHash),
    ];

    for (configured, expected) in policies {
        let mut config = pool("p", ("10.0.0.1", 80));
        config.lb_policy = configured;

        assert_eq!(pool_specs(&[config])[0].policy, expected);
    }
}

#[test]
fn a_backend_keeps_the_authority_of_its_upstream() {
    // The authority places a backend on a ring_hash ring: the same
    // backend must land on the same points as before the conversion.
    for host in ["backend.example", "10.0.0.1", "2001:db8::1"] {
        let config = pool("p", (host, 443));

        let backend = &pool_specs(std::slice::from_ref(&config))[0].backends[0];

        assert_eq!(backend.authority(), config.upstreams[0].authority());
    }
}
