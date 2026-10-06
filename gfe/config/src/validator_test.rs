use super::*;
use crate::{
    CertEntry, Listener, ListenerId, PoolId, Route, RouteId, Scheme, Upstream, UpstreamPool,
};

// ───────────────────────── Dynamic config ─────────────────────────

fn listener() -> Listener {
    Listener {
        id: ListenerId("https".into()),
        address: "0.0.0.0".parse().unwrap(),
        port: 443,
        protocol: ListenProtocol::Http, // http to avoid cert requirement
    }
}

fn pool(id: &str) -> UpstreamPool {
    UpstreamPool {
        id: PoolId(id.into()),
        scheme: Scheme::Http,
        lb_policy: Default::default(),
        upstreams: vec![Upstream {
            host: "10.0.0.1".into(),
            port: 80,
            weight: 1,
        }],
        health_check: None,
        max_in_flight: None,
    }
}

fn route(id: &str, pool: &str) -> Route {
    Route {
        id: RouteId(id.into()),
        listener: ListenerId("https".into()),
        host: "a.example.org".into(),
        path_prefix: "/".into(),
        action: RouteAction::Forward(pool.into()),
    }
}

#[test]
fn valid_config_passes() {
    let cfg = DynamicConfig {
        listeners: vec![listener()],
        pools: vec![pool("p")],
        routes: vec![route("r", "p")],
        ..Default::default()
    };
    assert!(validate(&cfg).is_ok());
}

#[test]
fn config_without_listeners_fails() {
    let cfg = DynamicConfig {
        pools: vec![pool("p")],
        ..Default::default()
    };

    let err = validate(&cfg).unwrap_err();

    assert!(err.to_string().contains("no listeners"), "{err}");
}

#[test]
fn duplicate_listener_ids_fail() {
    let mut second = listener();
    second.port = 80;
    let cfg = DynamicConfig {
        listeners: vec![listener(), second],
        ..Default::default()
    };

    let err = validate(&cfg).unwrap_err();

    assert!(
        err.to_string().contains("duplicate listener id: https"),
        "{err}"
    );
}

#[test]
fn two_listeners_on_one_address_fail() {
    let mut second = listener();
    second.id = ListenerId("other".into());
    let cfg = DynamicConfig {
        listeners: vec![listener(), second],
        ..Default::default()
    };

    let err = validate(&cfg).unwrap_err();

    assert!(err.to_string().contains("reuses address"), "{err}");
}

#[test]
fn duplicate_pool_ids_fail() {
    let cfg = DynamicConfig {
        listeners: vec![listener()],
        pools: vec![pool("p"), pool("p")],
        ..Default::default()
    };

    let err = validate(&cfg).unwrap_err();

    assert!(err.to_string().contains("duplicate pool id: p"), "{err}");
}

#[test]
fn pool_without_upstreams_fails() {
    let mut p = pool("p");
    p.upstreams.clear();

    let err = validate(&config_with_pool(p)).unwrap_err();

    assert!(err.to_string().contains("pool p has no upstreams"), "{err}");
}

#[test]
fn duplicate_route_ids_fail() {
    let cfg = DynamicConfig {
        listeners: vec![listener()],
        pools: vec![pool("p")],
        routes: vec![route("r", "p"), route("r", "p")],
        ..Default::default()
    };

    let err = validate(&cfg).unwrap_err();

    assert!(err.to_string().contains("duplicate route id: r"), "{err}");
}

#[test]
fn route_on_an_unknown_listener_fails() {
    let mut r = route("r", "p");
    r.listener = ListenerId("missing".into());
    let cfg = DynamicConfig {
        listeners: vec![listener()],
        pools: vec![pool("p")],
        routes: vec![r],
        ..Default::default()
    };

    let err = validate(&cfg).unwrap_err();

    assert!(
        err.to_string().contains("unknown listener missing"),
        "{err}"
    );
}

#[test]
fn dangling_pool_ref_fails() {
    let cfg = DynamicConfig {
        listeners: vec![listener()],
        pools: vec![pool("p")],
        routes: vec![route("r", "missing")],
        ..Default::default()
    };
    assert!(validate(&cfg).is_err());
}

#[test]
fn route_with_an_empty_host_fails() {
    let mut r = route("r", "p");
    r.host.clear();
    let cfg = DynamicConfig {
        listeners: vec![listener()],
        pools: vec![pool("p")],
        routes: vec![r],
        ..Default::default()
    };

    let err = validate(&cfg).unwrap_err();

    assert!(err.to_string().contains("route r has empty host"), "{err}");
}

#[test]
fn https_without_certs_fails() {
    let mut l = listener();
    l.protocol = ListenProtocol::Https;
    let cfg = DynamicConfig {
        listeners: vec![l],
        ..Default::default()
    };
    assert!(validate(&cfg).is_err());
}

#[test]
fn two_defaults_fail() {
    let mk = || CertEntry {
        sni: vec![],
        default: true,
        cert_file: "/c.pem".into(),
        key_file: "/k.pem".into(),
    };
    let cfg = DynamicConfig {
        certificates: vec![mk(), mk()],
        listeners: vec![listener()],
        ..Default::default()
    };
    let err = validate(&cfg).unwrap_err();
    assert!(err.to_string().contains("default certificate"), "{err}");
}

/// A valid config whose only pool is `pool`.
fn config_with_pool(pool: UpstreamPool) -> DynamicConfig {
    DynamicConfig {
        listeners: vec![listener()],
        pools: vec![pool],
        ..Default::default()
    }
}

fn backend(host: &str, weight: u32) -> Upstream {
    Upstream {
        host: host.into(),
        port: 80,
        weight,
    }
}

#[test]
fn upstream_weight_at_the_limit_passes() {
    let mut p = pool("p");
    p.upstreams = vec![backend("10.0.0.1", MAX_UPSTREAM_WEIGHT)];

    assert!(validate(&config_with_pool(p)).is_ok());
}

#[test]
fn upstream_weight_above_the_limit_fails() {
    let mut p = pool("p");
    p.upstreams = vec![backend("10.0.0.1", MAX_UPSTREAM_WEIGHT + 1)];

    let err = validate(&config_with_pool(p)).unwrap_err().to_string();

    assert!(err.contains("pool p"), "{err}");
    assert!(err.contains("1000"), "{err}");
}

#[test]
fn upstream_with_port_zero_fails() {
    let mut p = pool("p");
    p.upstreams[0].port = 0;

    let err = validate(&config_with_pool(p)).unwrap_err().to_string();

    assert!(err.contains("pool p has an invalid upstream"), "{err}");
}

/// What `validate` says about a pool whose only upstream is `host`.
fn validate_upstream_host(host: &str) -> Result<(), ConfigError> {
    let mut p = pool("p");
    p.upstreams = vec![backend(host, 1)];
    validate(&config_with_pool(p))
}

#[test]
fn upstream_hostnames_and_ip_literals_pass() {
    for host in [
        "app.example.org",
        "backend-1",
        "10.0.0.1",
        "2001:db8::1",
        "::1",
    ] {
        assert!(validate_upstream_host(host).is_ok(), "{host}");
    }
}

#[test]
fn bracketed_ipv6_upstream_fails_with_how_to_write_it() {
    let err = validate_upstream_host("[2001:db8::1]")
        .unwrap_err()
        .to_string();

    assert!(err.contains("without brackets"), "{err}");
}

#[test]
fn upstream_host_that_is_neither_a_hostname_nor_an_ip_fails() {
    for host in [
        "app example.org",
        "app/x",
        "-app.example.org",
        "app..example.org",
        "10.0.0.1:80",
    ] {
        let err = validate_upstream_host(host).unwrap_err().to_string();

        assert!(err.contains("pool p"), "{host}: {err}");
    }
}

/// The error `validate` gives for a pool `p` with the check `check`.
fn pool_check_error(check: HealthCheckConfig) -> String {
    let mut p = pool("p");
    p.health_check = Some(check);
    validate(&config_with_pool(p)).unwrap_err().to_string()
}

#[test]
fn pool_with_a_valid_health_check_passes() {
    let mut p = pool("p");
    p.health_check = Some(HealthCheckConfig {
        interval: Duration::from_millis(100),
        drain_status: Some(503),
        ..Default::default()
    });

    assert!(validate(&config_with_pool(p)).is_ok());
}

#[test]
fn health_check_with_a_zero_timeout_fails() {
    let err = pool_check_error(HealthCheckConfig {
        timeout: Duration::ZERO,
        ..Default::default()
    });

    assert!(err.contains("pool p: health_check.timeout"), "{err}");
}

#[test]
fn health_check_with_an_interval_below_100ms_fails() {
    let err = pool_check_error(HealthCheckConfig {
        interval: Duration::from_millis(99),
        ..Default::default()
    });

    assert!(err.contains("pool p: health_check.interval"), "{err}");
}

#[test]
fn health_check_with_a_relative_path_fails() {
    let err = pool_check_error(HealthCheckConfig {
        path: "healthz".into(),
        ..Default::default()
    });

    assert!(err.contains("pool p: health_check.path"), "{err}");
}

#[test]
fn health_check_with_an_impossible_expected_status_fails() {
    let err = pool_check_error(HealthCheckConfig {
        expected_status: 600,
        ..Default::default()
    });

    assert!(
        err.contains("pool p: health_check.expected_status"),
        "{err}"
    );
}

#[test]
fn health_check_with_an_impossible_drain_status_fails() {
    let err = pool_check_error(HealthCheckConfig {
        drain_status: Some(99),
        ..Default::default()
    });

    assert!(err.contains("pool p: health_check.drain_status"), "{err}");
}

// ───────────────────────── Bootstrap config ─────────────────────────

/// A minimal bootstrap config with `extra` appended to the
/// `[health_check_defaults]` section (so `extra` may also start new
/// tables), and what `validate_node_config` says about it.
fn validate_node(extra: &str) -> Result<(), String> {
    let toml = format!(
        "[node]\nid = \"t\"\n\n\
         [control_plane]\nconfig_file = \"/etc/gfe/gfe-dynamic.json\"\n\n\
         [health_check_defaults]\n{extra}\n"
    );
    let config: NodeConfig = toml::from_str(&toml).unwrap();
    validate_node_config(&config)
}

#[test]
fn accepts_default_health_check_defaults() {
    assert!(validate_node("").is_ok());
}

#[test]
fn rejects_max_header_bytes_below_minimum() {
    let err = validate_node("\n[limits]\nmax_header_bytes = 1024").unwrap_err();

    assert!(err.contains("max_header_bytes"), "{err}");
}

#[test]
fn rejects_health_check_defaults_with_a_zero_timeout() {
    let err = validate_node("timeout = \"0s\"").unwrap_err();

    assert!(err.contains("health_check_defaults.timeout"), "{err}");
}

#[test]
fn rejects_health_check_defaults_with_an_interval_below_100ms() {
    let err = validate_node("interval = \"10ms\"").unwrap_err();

    assert!(err.contains("health_check_defaults.interval"), "{err}");
}

#[test]
fn rejects_health_check_defaults_with_a_relative_path() {
    let err = validate_node("path = \"healthz\"").unwrap_err();

    assert!(err.contains("health_check_defaults.path"), "{err}");
}

#[test]
fn rejects_health_check_defaults_with_an_impossible_status() {
    let err = validate_node("expected_status = 1000").unwrap_err();

    assert!(
        err.contains("health_check_defaults.expected_status"),
        "{err}"
    );
}

#[test]
fn rejects_a_zero_limit() {
    for limit in [
        "max_connections",
        "max_connections_listener",
        "max_h2_concurrent_streams",
        "max_upstream_connections",
    ] {
        let err = validate_node(&format!("\n[limits]\n{limit} = 0")).unwrap_err();

        assert!(err.contains(&format!("limits.{limit}")), "{err}");
    }
}

#[test]
fn rejects_a_zero_timeout() {
    for timeout in [
        "tls_handshake",
        "request_header",
        "upstream_connect",
        "upstream_first_byte",
        "request_total",
        "client_idle",
        "drain_deadline",
    ] {
        let err = validate_node(&format!("\n[timeouts]\n{timeout} = \"0s\"")).unwrap_err();

        assert!(err.contains(&format!("timeouts.{timeout}")), "{err}");
    }
}

#[test]
fn rejects_zero_idle_upstream_connections() {
    let err = validate_node("\n[upstream]\nidle_connections = 0").unwrap_err();

    assert!(err.contains("upstream.idle_connections"), "{err}");
}

#[test]
fn rejects_an_upstream_client_certificate_without_its_key() {
    let err =
        validate_node("\n[upstream]\nclient_cert_file = \"/etc/gfe/client.crt\"").unwrap_err();

    assert!(err.contains("upstream.client_key_file"), "{err}");
}

#[test]
fn rejects_an_upstream_client_key_without_its_certificate() {
    let err = validate_node("\n[upstream]\nclient_key_file = \"/etc/gfe/client.key\"").unwrap_err();

    assert!(err.contains("upstream.client_cert_file"), "{err}");
}

#[test]
fn accepts_an_upstream_client_certificate_with_its_key() {
    let extra = "\n[upstream]\nclient_cert_file = \"/etc/gfe/client.crt\"\n\
                 client_key_file = \"/etc/gfe/client.key\"";

    assert!(validate_node(extra).is_ok());
}
