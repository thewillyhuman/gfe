use super::*;
use crate::handler::test_support::{node_config, state, state_with, temp_file};
use gfe_config::{DynamicConfig, ListenerId, PoolId, Route, RouteAction, RouteId, UpstreamPool};

#[test]
fn state_says_how_many_upstream_connections_the_node_may_open() {
    let mut config = node_config();
    config.limits.max_upstream_connections = 7;

    let state = state_with(&config);

    assert!(
        state
            .metrics()
            .encode()
            .contains("gfe_upstream_connections_limit 7")
    );
}

#[test]
fn refreshing_the_metrics_says_how_many_upstream_connections_are_open() {
    let state = state();
    state.metrics().proxy.upstream_connections.set(5);

    state.refresh_metrics();

    assert!(
        state
            .metrics()
            .encode()
            .contains("gfe_upstream_connections 0")
    );
}

#[test]
fn swap_installs_routes_and_pools_together() {
    let state = state();
    let config = DynamicConfig {
        routes: vec![Route {
            id: RouteId("r".into()),
            listener: ListenerId("http".into()),
            host: "*".into(),
            path_prefix: "/".into(),
            action: RouteAction::Forward("p".into()),
        }],
        pools: vec![UpstreamPool {
            id: PoolId("p".into()),
            scheme: Default::default(),
            lb_policy: Default::default(),
            upstreams: vec![],
            health_check: None,
            max_in_flight: None,
        }],
        ..Default::default()
    };

    state.swap(
        RouteTable::compile(&config),
        PoolSet::build(&crate::reload::pool_specs(&config.pools)).unwrap(),
    );

    let routing = state.routing.load();
    assert_eq!(routing.routes.route_count(), 1);
    assert_eq!(routing.pools.len(), 1);
}

#[test]
fn keeps_every_idle_connection_per_backend_unless_told_otherwise() {
    let mut config = node_config();

    let unset = client_options(&config).unwrap();
    config.upstream.idle_per_host = Some(0);
    let zero = client_options(&config).unwrap();
    config.upstream.idle_per_host = Some(4);
    let four = client_options(&config).unwrap();

    assert_eq!(unset.idle_per_host, usize::MAX);
    assert_eq!(zero.idle_per_host, usize::MAX);
    assert_eq!(four.idle_per_host, 4);
}

#[test]
fn client_is_held_to_the_upstream_timeouts_and_limit() {
    let mut config = node_config();
    config.timeouts.upstream_connect = Duration::from_secs(2);
    config.timeouts.upstream_first_byte = Duration::from_secs(20);
    config.upstream.idle_timeout = Duration::from_secs(50);
    config.limits.max_upstream_connections = 9;

    let options = client_options(&config).unwrap();

    assert_eq!(options.connect_timeout, Some(Duration::from_secs(2)));
    assert_eq!(options.idle_timeout, Some(Duration::from_secs(50)));
    assert_eq!(options.max_connections, Some(9));
    // A connection silent for as long as a backend may take to start
    // responding is asked for a sign of life, and has as long to give it
    // as it has to be opened.
    assert_eq!(
        options.http2_keep_alive,
        Some(KeepAlive {
            idle: Duration::from_secs(20),
            timeout: Duration::from_secs(2),
        })
    );
}

#[test]
fn refuses_an_unreadable_extra_ca_file() {
    let mut config = node_config();
    config.upstream.extra_ca_file = Some("/nonexistent/ca.pem".into());

    let error = State::new(&config, Arc::new(GfeMetrics::new())).unwrap_err();

    assert!(error.to_string().contains("extra_ca_file"), "{error}");
    assert!(error.to_string().contains("/nonexistent/ca.pem"), "{error}");
}

#[test]
fn refuses_an_extra_ca_file_without_a_certificate() {
    let mut config = node_config();
    let file = temp_file(b"not a certificate");
    config.upstream.extra_ca_file = Some(file.clone());

    let error = State::new(&config, Arc::new(GfeMetrics::new())).unwrap_err();

    assert!(
        error.to_string().contains(&file.display().to_string()),
        "{error}"
    );
}

#[test]
fn trusts_the_certificates_of_the_extra_ca_file() {
    let ca = rcgen::generate_simple_self_signed(vec!["ca.example.org".into()]).unwrap();
    let mut config = node_config();
    config.upstream.extra_ca_file = Some(temp_file(ca.cert.pem().as_bytes()));

    assert!(State::new(&config, Arc::new(GfeMetrics::new())).is_ok());
}

#[test]
fn refuses_a_client_certificate_without_its_key() {
    let mut config = node_config();
    config.upstream.client_cert_file = Some("/nonexistent/client.pem".into());

    let error = State::new(&config, Arc::new(GfeMetrics::new())).unwrap_err();

    assert!(
        matches!(error, ProxyError::IncompleteClientCertificate),
        "{error}"
    );
}

#[test]
fn refuses_a_client_key_that_is_not_one() {
    let client = rcgen::generate_simple_self_signed(vec!["client.example.org".into()]).unwrap();
    let mut config = node_config();
    let key = temp_file(b"not a key");
    config.upstream.client_cert_file = Some(temp_file(client.cert.pem().as_bytes()));
    config.upstream.client_key_file = Some(key.clone());

    let error = State::new(&config, Arc::new(GfeMetrics::new())).unwrap_err();

    assert!(
        error.to_string().contains(&key.display().to_string()),
        "{error}"
    );
}

#[test]
fn presents_a_usable_client_certificate() {
    let client = rcgen::generate_simple_self_signed(vec!["client.example.org".into()]).unwrap();
    let mut config = node_config();
    config.upstream.client_cert_file = Some(temp_file(client.cert.pem().as_bytes()));
    config.upstream.client_key_file = Some(temp_file(client.key_pair.serialize_pem().as_bytes()));

    assert!(State::new(&config, Arc::new(GfeMetrics::new())).is_ok());
}
