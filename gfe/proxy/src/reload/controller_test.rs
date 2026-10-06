use super::*;
use crate::listener::{Connections, Drain, Shared};
use crate::proxy;
use crate::proxy::test_support::node_config;
use crate::reload::test_support::{http_listener, scratch_dir};
use netkit_observability::GfeMetrics;
use std::path::Path;

/// A node whose dynamic config is `dir/gfe-dynamic.json`, with a
/// last-known-good cache `dir/config-cache.json`.
fn node(dir: &Path) -> NodeConfig {
    let mut node = node_config();
    node.control_plane.config_file = dir.join("gfe-dynamic.json");
    node.control_plane.local_cache = Some(dir.join("config-cache.json"));
    node.control_plane.reload_debounce = Duration::from_millis(20);
    node
}

/// The state and listeners of a node, with nothing applied yet.
fn parts(node: &NodeConfig) -> (Arc<State>, Arc<Listeners<App>>, Drain) {
    let drain = Drain::new();
    let metrics = Arc::new(GfeMetrics::new());
    let state = State::new(
        node,
        Arc::clone(&metrics),
        Connections::new(),
        drain.subscribe(),
    )
    .unwrap();
    let shared = Arc::new(Shared::new(
        metrics,
        node.limits.clone(),
        node.timeouts.clone(),
    ));
    let tls =
        netkit_tls::server_config(Arc::clone(state.resolver()), node.tls.min_version).unwrap();
    let listeners = Arc::new(Listeners::new(
        shared,
        proxy::app(Arc::clone(&state)),
        netkit_tls::Acceptor::new(Arc::new(tls)),
        Arc::clone(state.connections()),
        drain.subscribe(),
    ));
    (state, listeners, drain)
}

/// A config with one plaintext listener `id` on a free loopback port.
fn config_listening(id: &str) -> DynamicConfig {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    DynamicConfig {
        listeners: vec![http_listener(id, port)],
        ..Default::default()
    }
}

fn write(path: &Path, config: &DynamicConfig) {
    std::fs::write(path, serde_json::to_vec(config).unwrap()).unwrap();
}

fn metric(state: &State, line: &str) -> bool {
    state.metrics().encode().lines().any(|l| l == line)
}

#[tokio::test]
async fn starts_from_the_deployed_config_and_caches_it() {
    let dir = scratch_dir("controller-deployed");
    let node = node(&dir);
    let config = config_listening("deployed");
    write(&node.control_plane.config_file, &config);
    let (state, listeners, _drain) = parts(&node);

    let _controller = Controller::start(
        Arc::clone(&state),
        Arc::clone(&listeners),
        &node,
        CERT_POLL_INTERVAL,
    )
    .unwrap();

    assert!(listeners.local_addr(&config.listeners[0].id).is_some());
    let cached = load_dynamic_config(&dir.join("config-cache.json")).unwrap();
    assert_eq!(cached.listeners, config.listeners);
    assert!(metric(&state, "gfe_config_from_cache 0"));
    assert!(metric(&state, "gfe_config_reload_failed 0"));
}

#[tokio::test]
async fn starts_from_the_cache_when_the_deployed_config_is_missing() {
    let dir = scratch_dir("controller-cache");
    let node = node(&dir);
    let cached = config_listening("cached");
    write(&dir.join("config-cache.json"), &cached);
    let (state, listeners, _drain) = parts(&node);

    let _controller = Controller::start(
        Arc::clone(&state),
        Arc::clone(&listeners),
        &node,
        CERT_POLL_INTERVAL,
    )
    .unwrap();

    assert!(listeners.local_addr(&cached.listeners[0].id).is_some());
    assert!(metric(&state, "gfe_config_from_cache 1"));
    assert!(metric(&state, "gfe_config_reload_failed 1"));
    assert!(metric(&state, "gfe_config_reload_errors_total 1"));
}

#[tokio::test]
async fn refuses_to_start_with_neither_config_nor_cache_and_names_both() {
    let dir = scratch_dir("controller-neither");
    let node = node(&dir);
    let (state, listeners, _drain) = parts(&node);

    let error = Controller::start(state, listeners, &node, CERT_POLL_INTERVAL).unwrap_err();

    let message = error.to_string();
    assert!(message.contains("gfe-dynamic.json"), "{message}");
    assert!(message.contains("config-cache.json"), "{message}");
}

#[tokio::test]
async fn refuses_to_start_without_a_cache_when_the_deployed_config_is_missing() {
    let dir = scratch_dir("controller-no-cache");
    let mut node = node(&dir);
    node.control_plane.local_cache = None;
    let (state, listeners, _drain) = parts(&node);

    let error = Controller::start(state, listeners, &node, CERT_POLL_INTERVAL).unwrap_err();

    assert!(matches!(error, ReloadError::Config(_)), "{error}");
}

#[tokio::test]
async fn a_rejected_reload_keeps_the_running_config_and_says_so() {
    let dir = scratch_dir("controller-rejected");
    let node = node(&dir);
    let config = config_listening("running");
    write(&node.control_plane.config_file, &config);
    let (state, listeners, _drain) = parts(&node);
    let controller = Controller::start(
        Arc::clone(&state),
        Arc::clone(&listeners),
        &node,
        CERT_POLL_INTERVAL,
    )
    .unwrap();
    std::fs::write(&node.control_plane.config_file, b"not json").unwrap();

    controller.reloader.reload();

    assert!(listeners.local_addr(&config.listeners[0].id).is_some());
    assert!(metric(&state, "gfe_config_reload_failed 1"));
    assert!(metric(&state, "gfe_config_reload_errors_total 1"));
    // The cache still holds the config that runs.
    let cached = load_dynamic_config(&dir.join("config-cache.json")).unwrap();
    assert_eq!(cached.listeners, config.listeners);
}

#[tokio::test]
async fn a_controller_shut_down_applies_no_more_changes() {
    let dir = scratch_dir("controller-shutdown");
    let node = node(&dir);
    let config = config_listening("first");
    write(&node.control_plane.config_file, &config);
    let (state, listeners, _drain) = parts(&node);
    let controller = Controller::start(
        Arc::clone(&state),
        Arc::clone(&listeners),
        &node,
        CERT_POLL_INTERVAL,
    )
    .unwrap();
    let next = config_listening("second");
    write(&node.control_plane.config_file, &next);

    controller.shutdown();
    controller.reloader.reload();

    assert!(listeners.local_addr(&next.listeners[0].id).is_none());
    assert!(listeners.local_addr(&config.listeners[0].id).is_some());
}
