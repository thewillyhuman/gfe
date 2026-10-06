//! The limits a node puts on itself: a pool's quota of requests in flight,
//! the upstream connections it may open, and the size of a request head.

mod common;

use common::node::Node;
use common::*;
use gfe_config::RouteAction;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// [`forwarding_config`] plus `b.example.org` forwarded to a pool of its
/// own, `other`, whose backend is `other`; the pool of `a.example.org` may
/// have `max_in_flight` requests in flight at once.
fn two_pool_config(
    upstream: SocketAddr,
    max_in_flight: u32,
    other: SocketAddr,
) -> gfe_config::DynamicConfig {
    let mut cfg = forwarding_config(upstream);
    cfg.pools[0].max_in_flight = std::num::NonZeroU32::new(max_in_flight);
    cfg.pools
        .push(pool("other", gfe_config::Scheme::Http, &[other]));
    cfg.routes.push(route(
        "other",
        "b.example.org",
        "/",
        RouteAction::Forward("other".into()),
    ));
    cfg
}

#[tokio::test]
async fn answers_503_when_a_pool_has_max_in_flight_requests() {
    let (logs, _guard) = CapturedLogs::start();
    let slow = spawn_upstream_answering_after(Duration::from_millis(500)).await;
    let other = spawn_upstream().await;
    let proxy = Proxy::start(&two_pool_config(slow, 1, other)).await;
    let addr = proxy.addr;

    let first = tokio::spawn(async move { http_get(addr, "a.example.org", "/first").await });
    proxy
        .wait_for_metric(&format!(
            r#"gfe_upstream_requests_in_flight{{pool="pool",backend="{slow}"}} 1"#
        ))
        .await;
    let (refused_status, refused_body) = http_get(addr, "a.example.org", "/second").await;
    let (other_status, _) = http_get(addr, "b.example.org", "/").await;
    let (first_status, _) = first.await.unwrap();
    proxy
        .wait_for_metric(&format!(
            r#"gfe_upstream_requests_in_flight{{pool="pool",backend="{slow}"}} 0"#
        ))
        .await;
    let (later_status, _) = http_get(addr, "a.example.org", "/third").await;
    let refused = logs.access_event_for("/second").await;

    assert_eq!(refused_status, 503);
    assert!(
        refused_body.starts_with("503 upstream pool full"),
        "{refused_body}"
    );
    assert_eq!(other_status, 200);
    assert_eq!(first_status, 200);
    assert_eq!(later_status, 200);
    assert_eq!(refused["error"], "upstream_pool_full");
    assert_eq!(refused["pool"], "pool");
    assert_eq!(refused["attempts"], 0);
    proxy
        .wait_for_metric(r#"gfe_upstream_pool_full_total{pool="pool"} 1"#)
        .await;
}

#[tokio::test]
async fn answers_503_at_the_upstream_connection_limit() {
    let (logs, _guard) = CapturedLogs::start();
    let upstream = spawn_upstream_answering_after(Duration::from_millis(400)).await;
    let mut node = node_config();
    node.limits.max_upstream_connections = 1;
    node.upstream.idle_timeout = Duration::from_millis(300);
    let proxy = Proxy::start_with(&forwarding_config(upstream), node, None).await;
    let addr = proxy.addr;
    proxy
        .wait_for_metric("gfe_upstream_connections_limit 1")
        .await;

    // The first request holds the only upstream connection the node may open.
    let first = tokio::spawn(async move { http_get(addr, "a.example.org", "/first").await });
    proxy.wait_for_metric("gfe_upstream_connections 1").await;
    let (second_status, second_body) = http_get(addr, "a.example.org", "/second").await;
    let (first_status, _) = first.await.unwrap();
    // Once it is back in the pool, the connection serves the next request.
    let (third_status, _) = http_get(addr, "a.example.org", "/third").await;
    let refused = logs.access_event_for("/second").await;

    assert_eq!(first_status, 200);
    assert_eq!(second_status, 503);
    assert!(
        second_body.starts_with("503 upstream connection limit"),
        "{second_body}"
    );
    assert_eq!(third_status, 200);
    assert_eq!(refused["error"], "upstream_connection_limit");
    // A node-wide limit is not something another backend selection can fix.
    assert_eq!(refused["attempts"], 1);
    let metrics = proxy.metrics();
    assert!(
        metrics.contains(&format!(
            r#"gfe_upstream_errors_total{{pool="pool",backend="{upstream}",kind="connection_limit"}} 1"#
        )),
        "{metrics}"
    );
    assert!(
        !metrics.contains("gfe_upstream_connect_errors_total 1"),
        "{metrics}"
    );
    // An idle connection is closed after `idle_timeout`, and no longer counts.
    proxy.wait_for_metric("gfe_upstream_connections 0").await;
}

/// A head over `max_header_bytes` is answered by HTTP itself, before there
/// is a request: no access event, and the connection says why it closed.
#[tokio::test]
async fn rejects_request_headers_larger_than_max_header_bytes() {
    let (logs, _guard) = CapturedLogs::start();
    let node = Node::serving_with("header-bytes", &fixed_response_config(), |node| {
        node.limits.max_header_bytes = 8192;
    });

    // A request head that fills the whole limit without ever ending. Sending
    // exactly the limit (and no more) keeps the close clean: the server has
    // nothing left unread, so the client sees the response, not a reset.
    let mut stream = TcpStream::connect(node.addr("http")).await.unwrap();
    let prefix = "GET / HTTP/1.1\r\nhost: a.example.org\r\nx-padding: ";
    let request = format!("{prefix}{}", "a".repeat(8192 - prefix.len()));
    stream.write_all(request.as_bytes()).await.unwrap();
    let received = read_until_closed(&mut stream).await;
    let closed = logs.wait_for_events("gfe::conn", 1).await;

    assert!(received.starts_with("HTTP/1.1 431"), "{received}");
    assert_eq!(closed[0]["reason"], "protocol_error", "{closed:?}");
    assert!(
        logs.access_events().is_empty(),
        "{:?}",
        logs.access_events()
    );
}

#[tokio::test]
async fn serves_request_headers_within_max_header_bytes() {
    let mut node = node_config();
    node.limits.max_header_bytes = 8192;
    let proxy = Proxy::start_with(&fixed_response_config(), node, None).await;

    let padding = "a".repeat(7000);
    let response = raw_exchange(
        proxy.addr,
        &format!("GET / HTTP/1.1\r\nhost: a.example.org\r\nx-padding: {padding}\r\nconnection: close\r\n\r\n"),
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}
