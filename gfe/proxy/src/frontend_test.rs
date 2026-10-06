use super::*;
use crate::handler::test_support::node_config;
use gfe_config::{ListenProtocol, Listener, Route, RouteAction, RouteId};

fn listener() -> Listener {
    Listener {
        id: ListenerId("http".into()),
        address: "127.0.0.1".parse().unwrap(),
        port: 8080,
        protocol: ListenProtocol::Http,
    }
}

#[test]
fn check_accepts_a_valid_config_without_binding_its_listeners() {
    let config = DynamicConfig {
        listeners: vec![Listener {
            // Already in use: checking does not bind.
            port: std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port(),
            ..listener()
        }],
        ..Default::default()
    };

    Frontend::check(&config).unwrap();
}

#[test]
fn check_rejects_a_route_to_a_missing_pool() {
    let config = DynamicConfig {
        listeners: vec![listener()],
        routes: vec![Route {
            id: RouteId("r".into()),
            listener: ListenerId("http".into()),
            host: "*".into(),
            path_prefix: "/".into(),
            action: RouteAction::Forward("missing".into()),
        }],
        ..Default::default()
    };

    let error = Frontend::check(&config).unwrap_err();

    assert!(error.to_string().contains("missing"), "{error}");
}

#[tokio::test]
async fn refuses_to_start_without_a_config_and_says_which_file() {
    let mut node = node_config();
    node.control_plane.config_file = std::env::temp_dir()
        .join(format!("gfe-core-frontend-{}", std::process::id()))
        .join("gfe-dynamic.json");
    std::fs::create_dir_all(node.control_plane.config_file.parent().unwrap()).unwrap();

    let error = Frontend::start(&node, Arc::new(GfeMetrics::new()), Vec::new()).unwrap_err();

    assert!(error.to_string().contains("gfe-dynamic.json"), "{error}");
}

#[tokio::test]
async fn refuses_to_start_with_an_unusable_upstream_ca() {
    let mut node = node_config();
    node.upstream.extra_ca_file = Some("/nonexistent/ca.pem".into());

    let error = Frontend::start(&node, Arc::new(GfeMetrics::new()), Vec::new()).unwrap_err();

    assert!(matches!(error, StartError::Proxy(_)), "{error}");
}

/// A `client_idle` whose quarter (the PING timeout) rounds to zero would
/// fail every connection: the start fails instead.
#[tokio::test]
async fn refuses_to_start_with_client_timeouts_http_cannot_serve() {
    let mut node = node_config();
    node.timeouts.client_idle = Duration::from_nanos(3);

    let error = Frontend::start(&node, Arc::new(GfeMetrics::new()), Vec::new()).unwrap_err();

    assert!(matches!(error, StartError::Http(_)), "{error}");
}

/// The binary shares one front end between its ops endpoint and its signal
/// loop.
#[test]
fn can_be_shared_between_tasks() {
    fn shareable<T: Send + Sync + 'static>() {}
    shareable::<Frontend>();
}

#[test]
fn passes_the_configured_minimum_tls_version_to_the_library() {
    assert_eq!(
        tls_min_version(gfe_config::MinVersion::Tls12),
        netkit_tls::MinVersion::Tls12
    );
    assert_eq!(
        tls_min_version(gfe_config::MinVersion::Tls13),
        netkit_tls::MinVersion::Tls13
    );
}
