use super::*;
use crate::listener::Connections;
use crate::proxy::test_support::{node_config, state};
use gfe_observability::GfeMetrics;
use tokio::sync::watch;

#[test]
fn app_serves_cleartext_http2_by_prior_knowledge() {
    let app = app(state());

    let options = app.server_options.as_ref().unwrap();
    assert!(options.h2c);
}

#[test]
fn app_lets_connect_through_for_gfe_to_refuse() {
    let app = app(state());

    assert!(
        app.server_options
            .as_ref()
            .unwrap()
            .allow_connect_method_proxying
    );
}

#[test]
fn app_leaves_closing_idle_http2_connections_to_the_edge() {
    let app = app(state());

    assert_eq!(app.server_options.as_ref().unwrap().h2_idle_timeout, None);
    assert!(app.h2_options.is_some());
}

#[test]
fn state_says_how_many_upstream_connections_the_node_may_open() {
    let mut config = node_config();
    config.limits.max_upstream_connections = 7;
    let metrics = Arc::new(GfeMetrics::new());

    State::new(
        &config,
        Arc::clone(&metrics),
        Connections::new(),
        watch::channel(false).1,
    )
    .unwrap();

    assert!(
        metrics
            .encode()
            .contains("gfe_upstream_connections_limit 7")
    );
}

#[test]
fn state_refuses_an_unreadable_extra_ca_file() {
    let mut config = node_config();
    config.upstream.extra_ca_file = Some("/nonexistent/ca.pem".into());

    let error = State::new(
        &config,
        Arc::new(GfeMetrics::new()),
        Connections::new(),
        watch::channel(false).1,
    )
    .unwrap_err();

    assert!(error.to_string().contains("/nonexistent/ca.pem"), "{error}");
}

#[test]
fn swap_installs_routes_and_pools_together() {
    let state = state();
    let config = gfe_config::DynamicConfig {
        routes: vec![gfe_config::Route {
            id: gfe_config::RouteId("r".into()),
            listener: gfe_config::ListenerId("http".into()),
            host: "*".into(),
            path_prefix: "/".into(),
            action: RouteAction::Forward("p".into()),
        }],
        pools: vec![gfe_config::UpstreamPool {
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
        crate::routing::RouteTable::compile(&config),
        gfe_load_balancing::PoolSet::build(&config.pools).unwrap(),
    );

    let routing = state.routing.load();
    assert_eq!(routing.routes.route_count(), 1);
    assert_eq!(routing.pools.len(), 1);
}

#[test]
fn http1_keep_alive_outlasts_client_idle() {
    assert_eq!(keepalive_secs(Duration::from_secs(75)), 76);
    assert_eq!(keepalive_secs(Duration::from_millis(200)), 2);
    assert_eq!(keepalive_secs(Duration::from_millis(1500)), 3);
}
