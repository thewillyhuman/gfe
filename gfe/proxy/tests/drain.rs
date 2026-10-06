//! Draining a whole front end, with real requests through the proxy: what
//! a client in the middle of a request, between two requests, or on HTTP/2
//! sees, and when the drain ends.

mod common;

use common::node::{Node, eventually, free_port, listener};
use common::{
    CapturedLogs, forwarding_config, h2_sender, read_until_closed, spawn_silent_upstream,
    spawn_upstream, spawn_upstream_answering_after,
};
use gfe_config::ListenProtocol;
use http_body_util::BodyExt;
use netkit_http::Bytes;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nhost: a.example.org\r\n\r\n";

/// A node forwarding `a.example.org` on listener `http` to `upstream`,
/// draining for at most `deadline`.
fn node(test: &str, upstream: SocketAddr, deadline: Duration) -> Node {
    Node::serving_with(test, &forwarding_config(upstream), |node| {
        node.timeouts.drain_deadline = deadline;
    })
}

/// Read one response, whose body is known to end with `ends_with`, off
/// `stream`, leaving the connection open.
async fn read_response(stream: &mut TcpStream, ends_with: &str) -> String {
    let mut received = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(5);
    while !String::from_utf8_lossy(&received).ends_with(ends_with) {
        let read = tokio::time::timeout_at(deadline.into(), stream.read(&mut buf))
            .await
            .expect("a response should arrive")
            .unwrap();
        assert!(
            read > 0,
            "closed after {:?}",
            String::from_utf8_lossy(&received)
        );
        received.extend_from_slice(&buf[..read]);
    }
    String::from_utf8_lossy(&received).to_lowercase()
}

/// Wait until the backend `upstream` of pool `pool` has a request in flight.
async fn wait_in_flight(node: &Node, upstream: SocketAddr) {
    node.wait_for_metric(&format!(
        "gfe_upstream_requests_in_flight{{pool=\"pool\",backend=\"{upstream}\"}} 1"
    ))
    .await;
}

#[tokio::test]
async fn an_http1_request_in_flight_when_the_drain_starts_is_answered_with_connection_close() {
    let upstream = spawn_upstream_answering_after(Duration::from_millis(300)).await;
    let node = node("in-flight-h1", upstream, Duration::from_secs(10));
    let mut client = TcpStream::connect(node.addr("http")).await.unwrap();
    client.write_all(REQUEST).await.unwrap();
    wait_in_flight(&node, upstream).await;

    let started = Instant::now();
    let ((), answer) = tokio::join!(node.frontend.drain(), async {
        read_until_closed(&mut client).await.to_lowercase()
    });

    assert!(answer.starts_with("http/1.1 200"), "{answer}");
    assert!(answer.contains("connection: close"), "{answer}");
    // Closed with its answer, not when idle connections are closed at half
    // the deadline.
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn an_http2_client_is_sent_goaway_and_its_stream_in_flight_completes() {
    let upstream = spawn_upstream_answering_after(Duration::from_millis(300)).await;
    let node = node("in-flight-h2", upstream, Duration::from_secs(10));
    let mut sender = h2_sender(node.addr("http")).await;
    let req = netkit_http::Request::builder()
        .uri("http://a.example.org/")
        .body(common::ChannelBody::full(Bytes::new()))
        .unwrap();
    let in_flight = tokio::spawn(async move {
        let response = sender.send_request(req).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, body, sender)
    });
    wait_in_flight(&node, upstream).await;

    let ((), response) = tokio::join!(node.frontend.drain(), in_flight);

    let (status, body, sender) = response.unwrap();
    assert_eq!(status, 200);
    assert!(body.starts_with(b"upstream-ok"));
    // The GOAWAY closed the connection to new streams.
    assert!(eventually(async || sender.is_closed()).await);
}

#[tokio::test]
async fn an_idle_connection_may_send_one_more_request_answered_with_connection_close() {
    let (logs, _capturing) = CapturedLogs::start();
    let upstream = spawn_upstream().await;
    let node = node("one-more", upstream, Duration::from_secs(10));
    let mut client = TcpStream::connect(node.addr("http")).await.unwrap();
    client.write_all(REQUEST).await.unwrap();
    read_response(&mut client, "host=a.example.org").await;

    let ((), answer) = tokio::join!(node.frontend.drain(), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        client.write_all(REQUEST).await.unwrap();
        read_until_closed(&mut client).await.to_lowercase()
    });

    assert!(answer.starts_with("http/1.1 200"), "{answer}");
    assert!(answer.contains("connection: close"), "{answer}");
    let events = logs.wait_for_events("gfe::conn", 1).await;
    assert_eq!(events[0]["reason"], "drain");
    assert_eq!(events[0]["requests"], 2);
}

#[tokio::test]
async fn an_idle_connection_is_closed_between_half_the_deadline_and_the_deadline() {
    let (logs, _capturing) = CapturedLogs::start();
    let upstream = spawn_upstream().await;
    let node = node("idle", upstream, Duration::from_secs(1));
    let mut client = TcpStream::connect(node.addr("http")).await.unwrap();
    client.write_all(REQUEST).await.unwrap();
    read_response(&mut client, "host=a.example.org").await;

    let started = Instant::now();
    let ((), closed_after) = tokio::join!(node.frontend.drain(), async {
        read_until_closed(&mut client).await;
        started.elapsed()
    });

    assert!(
        closed_after >= Duration::from_millis(500),
        "{closed_after:?}"
    );
    assert!(closed_after < Duration::from_secs(1), "{closed_after:?}");
    let events = logs.wait_for_events("gfe::conn", 1).await;
    assert_eq!(events[0]["reason"], "drain");
}

#[tokio::test]
async fn the_drain_ends_as_soon_as_the_last_client_leaves() {
    let upstream = spawn_upstream().await;
    let node = node("last-leaves", upstream, Duration::from_secs(10));
    let mut client = TcpStream::connect(node.addr("http")).await.unwrap();
    client.write_all(REQUEST).await.unwrap();
    read_response(&mut client, "host=a.example.org").await;

    let started = Instant::now();
    tokio::join!(node.frontend.drain(), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(client);
    });

    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_node_without_connections_drains_at_once() {
    let node = node(
        "no-clients",
        spawn_upstream().await,
        Duration::from_secs(10),
    );

    let started = Instant::now();
    node.frontend.drain().await;

    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_request_still_in_flight_at_the_deadline_is_cut_and_accounted_for() {
    let (logs, _capturing) = CapturedLogs::start();
    let upstream = spawn_silent_upstream().await;
    let node = node("cut", upstream, Duration::from_secs(1));
    let mut client = TcpStream::connect(node.addr("http")).await.unwrap();
    client.write_all(REQUEST).await.unwrap();
    wait_in_flight(&node, upstream).await;

    let started = Instant::now();
    node.frontend.drain().await;

    let took = started.elapsed();
    assert!(took >= Duration::from_secs(1), "{took:?}");
    assert!(took < Duration::from_millis(2500), "{took:?}");
    let conn = logs.wait_for_events("gfe::conn", 1).await;
    assert_eq!(conn[0]["reason"], "shutdown");
    let access = logs.access_event().await;
    assert_eq!(access["status"], 499);
    assert!(node.has_metric("gfe_connections_active 0"));
}

#[tokio::test]
async fn a_draining_node_is_not_ready_accepts_nothing_and_follows_no_config_change() {
    let upstream = spawn_upstream().await;
    let node = node("leaving", upstream, Duration::from_secs(10));
    let addr = node.addr("http");
    // Kept open so that the drain lasts.
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(REQUEST).await.unwrap();
    read_response(&mut client, "host=a.example.org").await;
    let added = free_port();

    tokio::select! {
        biased;
        () = node.frontend.drain() => panic!("the drain ended with a client connected"),
        () = async {
            assert!(node.frontend.is_draining());
            assert!(eventually(async || TcpStream::connect(addr).await.is_err()).await);
            let mut config = forwarding_config(upstream);
            config.listeners.push(listener("added", ListenProtocol::Http, added));
            node.deploy(&config);
            // Long enough for a reload to have happened.
            tokio::time::sleep(Duration::from_millis(500)).await;
        } => {}
    }

    assert!(TcpStream::connect(("127.0.0.1", added)).await.is_err());
}
