//! Keeping a whole front end in step with its config: changes on disk reach
//! the proxy and the listeners without a restart, all or nothing, and the
//! last-known-good cache is what a node starts from when its deployed
//! config cannot be used.

mod common;

use common::node::{Node, bootstrap, eventually, free_port, listener, scratch, write_config};
use common::{http_get, pool, route, spawn_counting_upstream, spawn_upstream};
use gfe_config::{DynamicConfig, FixedAction, ListenProtocol, RouteAction, Scheme};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn fixed(body: &str) -> RouteAction {
    RouteAction::Fixed(FixedAction {
        status: 200,
        body: body.into(),
    })
}

/// Listener `http` on `port`, answering `body` to every host.
fn answering(port: u16, body: &str) -> DynamicConfig {
    DynamicConfig {
        listeners: vec![listener("http", ListenProtocol::Http, port)],
        routes: vec![route("all", "*", "/", fixed(body))],
        ..Default::default()
    }
}

/// What `GET /` for `host` on `addr` is answered, or `None` if nothing
/// listens there.
async fn body_at(addr: SocketAddr, host: &str) -> Option<String> {
    TcpStream::connect(addr).await.ok()?;
    let (status, body) = http_get(addr, host, "/").await;
    Some(format!("{status} {body}"))
}

#[tokio::test]
async fn serves_a_route_added_by_a_reload() {
    let mut config = answering(0, "first");
    config.routes[0].host = "a.example.org".into();
    let node = Node::serving("route-added", &config);
    let addr = node.addr("http");
    assert_eq!(http_get(addr, "b.example.org", "/").await.0, 404);

    config
        .routes
        .push(route("b", "b.example.org", "/", fixed("added")));
    node.deploy(&config);

    assert!(
        eventually(async || body_at(addr, "b.example.org").await.as_deref() == Some("200 added"))
            .await
    );
    node.wait_for_metric("gfe_active_routes 2").await;
}

#[tokio::test]
async fn forwards_to_a_pool_added_by_a_reload() {
    let upstream = spawn_upstream().await;
    let mut config = answering(0, "fixed");
    let node = Node::serving("pool-added", &config);
    let addr = node.addr("http");

    config.routes = vec![route("web", "*", "/", RouteAction::Forward("added".into()))];
    config.pools = vec![pool("added", Scheme::Http, &[upstream])];
    node.deploy(&config);

    assert!(
        eventually(async || body_at(addr, "a.example.org")
            .await
            .is_some_and(|body| body.starts_with("200 upstream-ok")))
        .await
    );
    node.wait_for_metric("gfe_active_pools 1").await;
}

#[tokio::test]
async fn stops_forwarding_to_a_pool_removed_by_a_reload() {
    let (kept, _, _) = spawn_counting_upstream().await;
    let (removed, removed_requests, _) = spawn_counting_upstream().await;
    let mut config = DynamicConfig {
        listeners: vec![listener("http", ListenProtocol::Http, 0)],
        routes: vec![
            route(
                "kept",
                "kept.example.org",
                "/",
                RouteAction::Forward("kept".into()),
            ),
            route(
                "gone",
                "gone.example.org",
                "/",
                RouteAction::Forward("gone".into()),
            ),
        ],
        pools: vec![
            pool("kept", Scheme::Http, &[kept]),
            pool("gone", Scheme::Http, &[removed]),
        ],
        ..Default::default()
    };
    let node = Node::serving("pool-removed", &config);
    let addr = node.addr("http");
    assert_eq!(http_get(addr, "gone.example.org", "/").await.0, 200);

    config.routes.pop();
    config.pools.pop();
    node.deploy(&config);

    assert!(eventually(async || http_get(addr, "gone.example.org", "/").await.0 == 404).await);
    let reached = removed_requests.load(Ordering::SeqCst);
    assert_eq!(http_get(addr, "gone.example.org", "/").await.0, 404);
    assert_eq!(http_get(addr, "kept.example.org", "/").await.0, 200);
    assert_eq!(removed_requests.load(Ordering::SeqCst), reached);
    node.wait_for_metric("gfe_active_pools 1").await;
}

#[tokio::test]
async fn binds_a_listener_added_by_a_reload() {
    let first = free_port();
    let node = Node::serving("listener-added", &answering(first, "first"));
    let added = free_port();
    let added_addr: SocketAddr = ([127, 0, 0, 1], added).into();
    assert!(TcpStream::connect(added_addr).await.is_err());

    let mut config = answering(first, "first");
    config
        .listeners
        .push(listener("added", ListenProtocol::Http, added));
    config.routes.push(added_route("on-added", "added"));
    node.deploy(&config);

    assert!(
        eventually(async || body_at(added_addr, "a").await.as_deref() == Some("200 added")).await
    );
}

/// A route on listener `added`.
fn added_route(id: &str, body: &str) -> gfe_config::Route {
    gfe_config::Route {
        listener: gfe_config::ListenerId("added".into()),
        ..route(id, "*", "/", fixed(body))
    }
}

#[tokio::test]
async fn stops_listening_on_a_removed_listener_and_finishes_its_open_connection() {
    let first = free_port();
    let removed = free_port();
    let mut config = answering(first, "first");
    config
        .listeners
        .push(listener("added", ListenProtocol::Http, removed));
    config.routes.push(added_route("on-added", "added"));
    let node = Node::serving("listener-removed", &config);
    let removed_addr: SocketAddr = ([127, 0, 0, 1], removed).into();
    let mut open = TcpStream::connect(removed_addr).await.unwrap();

    node.deploy(&answering(first, "first"));

    assert!(eventually(async || TcpStream::connect(removed_addr).await.is_err()).await);
    open.write_all(b"GET / HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    open.read_to_string(&mut response).await.unwrap();
    // The listener's routes went with it.
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");
}

#[tokio::test]
async fn no_request_fails_on_a_listener_kept_while_another_comes_and_goes() {
    let kept = free_port();
    let other = free_port();
    let base = answering(kept, "kept");
    let mut with_other = base.clone();
    with_other
        .listeners
        .push(listener("added", ListenProtocol::Http, other));
    with_other.routes.push(added_route("on-added", "added"));
    let node = Node::serving("listener-churn", &base);
    let addr: SocketAddr = ([127, 0, 0, 1], kept).into();

    let mut answered = 0;
    for round in 0..6 {
        node.deploy(if round % 2 == 0 { &with_other } else { &base });
        for _ in 0..20 {
            let (status, body) = http_get(addr, "a.example.org", "/").await;
            assert_eq!((status, body.as_str()), (200, "kept"));
            answered += 1;
        }
        tokio::time::sleep(Duration::from_millis(60)).await;
    }

    assert_eq!(answered, 120);
    assert!(node.has_metric("gfe_config_reload_failed 0"));
}

#[tokio::test]
async fn rejects_an_invalid_config_wholesale_and_keeps_serving() {
    let node = Node::serving("invalid", &answering(0, "running"));
    let addr = node.addr("http");
    let added = free_port();
    let mut invalid = answering(0, "replaced");
    invalid
        .listeners
        .push(listener("added", ListenProtocol::Http, added));
    invalid.routes.push(route(
        "dangling",
        "*",
        "/x",
        RouteAction::Forward("missing".into()),
    ));

    node.deploy(&invalid);

    node.wait_for_metric("gfe_config_reload_errors_total 1")
        .await;
    assert!(node.has_metric("gfe_config_reload_failed 1"));
    assert_eq!(body_at(addr, "a").await.as_deref(), Some("200 running"));
    assert!(TcpStream::connect(("127.0.0.1", added)).await.is_err());
}

#[tokio::test]
async fn rejects_a_config_whose_listener_cannot_be_bound() {
    let node = Node::serving("cannot-bind", &answering(0, "running"));
    let addr = node.addr("http");
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut config = answering(0, "replaced");
    let port = taken.local_addr().unwrap().port();
    config
        .listeners
        .push(listener("added", ListenProtocol::Http, port));
    config.routes.push(added_route("on-added", "added"));

    node.deploy(&config);

    node.wait_for_metric("gfe_config_reload_failed 1").await;
    // Nothing of the config was applied, not even what did not need the
    // socket.
    assert_eq!(body_at(addr, "a").await.as_deref(), Some("200 running"));
}

#[tokio::test]
async fn reports_a_rejected_reload_until_a_good_one() {
    let node = Node::serving("reload-failed", &answering(0, "first"));
    assert!(node.has_metric("gfe_config_reload_failed 0"));

    std::fs::write(node.dir.join("gfe-dynamic.json"), b"{ not json").unwrap();
    node.wait_for_metric("gfe_config_reload_failed 1").await;

    node.deploy(&answering(0, "second"));
    node.wait_for_metric("gfe_config_reload_failed 0").await;
    assert_eq!(
        body_at(node.addr("http"), "a").await.as_deref(),
        Some("200 second")
    );
}

#[tokio::test]
async fn writes_the_last_known_good_cache_on_each_applied_config_only() {
    let node = Node::serving("cache-written", &answering(0, "first"));
    let cache = node.dir.join("config-cache.json");
    let cached = || gfe_config::load_dynamic_config(&cache).unwrap();
    assert_eq!(cached().routes[0].action, fixed("first"));

    node.deploy(&answering(0, "second"));
    assert!(eventually(async || cached().routes[0].action == fixed("second")).await);

    std::fs::write(node.dir.join("gfe-dynamic.json"), b"{ not json").unwrap();
    node.wait_for_metric("gfe_config_reload_failed 1").await;
    assert_eq!(cached().routes[0].action, fixed("second"));
}

#[tokio::test]
async fn starts_from_the_cache_when_the_deployed_config_is_missing() {
    let dir = scratch("cache-missing");
    let port = free_port();
    write_config(&dir.join("config-cache.json"), &answering(port, "cached"));

    let node = Node::boot(dir.clone(), &bootstrap(&dir), Vec::new()).unwrap();

    let addr = ([127, 0, 0, 1], port).into();
    assert_eq!(body_at(addr, "a").await.as_deref(), Some("200 cached"));
    assert!(node.has_metric("gfe_config_from_cache 1"));
    assert!(node.has_metric("gfe_config_reload_failed 1"));
}

#[tokio::test]
async fn starts_from_the_cache_when_the_deployed_config_is_invalid() {
    let dir = scratch("cache-invalid");
    let port = free_port();
    write_config(&dir.join("config-cache.json"), &answering(port, "cached"));
    let mut invalid = answering(port, "deployed");
    invalid.routes[0].action = RouteAction::Forward("missing".into());
    write_config(&dir.join("gfe-dynamic.json"), &invalid);

    let node = Node::boot(dir.clone(), &bootstrap(&dir), Vec::new()).unwrap();

    let addr = ([127, 0, 0, 1], port).into();
    assert_eq!(body_at(addr, "a").await.as_deref(), Some("200 cached"));
    assert!(node.has_metric("gfe_config_from_cache 1"));
}

#[tokio::test]
async fn refuses_to_start_with_neither_a_dynamic_config_nor_a_cache() {
    let dir = scratch("cache-none");

    let error = Node::boot(dir.clone(), &bootstrap(&dir), Vec::new())
        .err()
        .expect("nothing to serve");

    let message = error.to_string();
    assert!(message.contains("gfe-dynamic.json"), "{message}");
    assert!(message.contains("config-cache.json"), "{message}");
}

#[tokio::test]
async fn leaves_the_cache_once_a_usable_config_is_deployed() {
    let dir = scratch("cache-recover");
    write_config(&dir.join("config-cache.json"), &answering(0, "cached"));
    let node = Node::boot(dir.clone(), &bootstrap(&dir), Vec::new()).unwrap();
    assert!(node.has_metric("gfe_config_from_cache 1"));

    node.deploy(&answering(0, "deployed"));

    let addr = node.addr("http");
    assert!(eventually(async || body_at(addr, "a").await.as_deref() == Some("200 deployed")).await);
    assert!(node.has_metric("gfe_config_from_cache 0"));
    assert!(node.has_metric("gfe_config_reload_failed 0"));
}

/// An in-place upgrade whose deployed config is invalid: the new node must
/// start from its cache on the sockets it inherited, because the node it
/// replaces still listens on those addresses and they cannot be bound.
#[tokio::test]
async fn starts_from_the_cache_on_inherited_sockets_when_the_deployed_config_is_invalid() {
    let dir = scratch("cache-inherited");
    let inherited = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = inherited.local_addr().unwrap();
    // The predecessor's copy of the socket: it keeps listening until the
    // new node has started.
    let _predecessor = inherited.try_clone().unwrap();
    write_config(
        &dir.join("config-cache.json"),
        &answering(addr.port(), "cached"),
    );
    let mut invalid = answering(addr.port(), "deployed");
    invalid.routes[0].action = RouteAction::Forward("missing".into());
    write_config(&dir.join("gfe-dynamic.json"), &invalid);

    let node = Node::boot(dir.clone(), &bootstrap(&dir), vec![(addr, inherited)]).unwrap();

    assert!(node.has_metric("gfe_config_from_cache 1"));
    assert_eq!(body_at(addr, "a").await.as_deref(), Some("200 cached"));
}

/// The upgrade in place: a successor started on the sockets a running node
/// lends it serves the connections that were waiting on them.
#[tokio::test]
async fn a_successor_serves_on_the_sockets_its_predecessor_lends_it() {
    let port = free_port();
    let predecessor = Node::serving("handover-old", &answering(port, "old"));
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let sockets = predecessor.frontend.sockets().unwrap();
    let dir = scratch("handover-new");
    write_config(&dir.join("gfe-dynamic.json"), &answering(port, "new"));

    let successor = Node::boot(dir.clone(), &bootstrap(&dir), sockets).unwrap();
    predecessor.frontend.drain().await;

    assert_eq!(body_at(addr, "a").await.as_deref(), Some("200 new"));
    drop(successor);
}

#[tokio::test]
async fn an_open_connection_follows_a_renamed_listener() {
    let port = free_port();
    let node = Node::serving("renamed", &answering(port, "before"));
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let mut client = TcpStream::connect(addr).await.unwrap();

    let mut renamed = answering(port, "after");
    renamed.listeners[0].id = gfe_config::ListenerId("renamed".into());
    renamed.routes[0].listener = gfe_config::ListenerId("renamed".into());
    node.deploy(&renamed);
    assert!(eventually(async || body_at(addr, "a").await.as_deref() == Some("200 after")).await);

    client
        .write_all(b"GET / HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).await.unwrap();
    assert!(response.ends_with("after"), "{response}");
}

/// A rotation writes the certificate, then the key. A poll in between finds
/// a key that does not match: that reload is rejected, and the next change
/// (the key) is applied.
#[tokio::test]
async fn a_certificate_caught_without_its_key_is_rejected_then_applied_with_it() {
    let dir = scratch("half-rotation");
    let first = rcgen::generate_simple_self_signed(vec!["a.example.org".into()]).unwrap();
    std::fs::write(dir.join("tls.crt"), first.cert.pem()).unwrap();
    std::fs::write(dir.join("tls.key"), first.key_pair.serialize_pem()).unwrap();
    let mut config = answering(0, "ok");
    config.certificates = vec![gfe_config::CertEntry {
        sni: vec!["a.example.org".into()],
        default: true,
        cert_file: dir.join("tls.crt"),
        key_file: dir.join("tls.key"),
    }];
    write_config(&dir.join("gfe-dynamic.json"), &config);
    let node = Node::boot(dir.clone(), &bootstrap(&dir), Vec::new()).unwrap();
    let second = rcgen::generate_simple_self_signed(vec!["a.example.org".into()]).unwrap();

    std::fs::write(dir.join("tls.crt"), second.cert.pem()).unwrap();
    node.wait_for_metric("gfe_config_reload_failed 1").await;
    std::fs::write(dir.join("tls.key"), second.key_pair.serialize_pem()).unwrap();

    node.wait_for_metric("gfe_config_reload_failed 0").await;
    assert_eq!(
        node.metrics()
            .matches("gfe_config_reload_errors_total 1")
            .count(),
        1
    );
}
