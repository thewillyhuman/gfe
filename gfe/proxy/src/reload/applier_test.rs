use super::*;
use crate::proxy::test_support::state;
use crate::reload::test_support::{cert_entry, http_listener};
use gfe_config::{
    CertEntry, ListenerId, PoolId, Route, RouteAction, RouteId, Scheme, Upstream, UpstreamPool,
};
use netkit_health_checking::HealthStatus;

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

    install(&state, prepare(&config()).unwrap());

    let routing = state.routing.load();
    assert_eq!(routing.routes.route_count(), 1);
    assert_eq!(routing.pools.len(), 1);
    assert!(state.resolver().current().resolve(None).is_some());
}

#[test]
fn install_describes_the_config_in_the_metrics() {
    let state = state();

    install(&state, prepare(&config()).unwrap());

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
    install(&state, prepare(&old).unwrap());

    install(&state, prepare(&new).unwrap());

    let exported = state.metrics().encode();
    assert!(!exported.contains("old.example.org"), "{exported}");
    assert!(exported.contains("new.example.org"), "{exported}");
}

#[test]
fn install_forgets_the_health_of_backends_no_longer_configured() {
    let state = state();
    install(&state, prepare(&config()).unwrap());
    state.health().set("10.0.0.1", 80, HealthStatus::Unhealthy);
    let moved = DynamicConfig {
        pools: vec![pool("p", ("10.0.0.2", 80))],
        ..config()
    };

    install(&state, prepare(&moved).unwrap());

    assert!(state.health().is_empty());
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

    let error = prepare(&config).unwrap_err();

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

    let error = prepare(&config).unwrap_err();

    assert!(error.to_string().contains("missing"), "{error}");
}

#[test]
fn prepare_changes_nothing_that_is_served() {
    let state = state();

    prepare(&config()).unwrap();

    assert_eq!(state.routing.load().routes.route_count(), 0);
    assert!(state.resolver().current().is_empty());
}
