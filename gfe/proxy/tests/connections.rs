//! Client connections to a whole front end: the edge's timeouts, limits and
//! connection log, with real requests through the proxy behind it. What the
//! edge does on its own is tested in `edge.rs`; this is what the two halves
//! do together.

mod common;

use bytes::Bytes;
use common::node::{Node, free_port, listener};
use common::{
    CapturedLogs, ChannelBody, fixed_response_config, forwarding_config, h2_sender, http_get,
    read_until_closed, serve_http1, spawn_upstream_answering_after,
};
use gfe_config::{DynamicConfig, ListenProtocol};
use http_body_util::Full;
use hyper::Response;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::watch;

const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nhost: a.example.org\r\n\r\n";

#[tokio::test]
async fn closes_a_connection_that_never_sends_a_request() {
    let (logs, _capturing) = CapturedLogs::start();
    let node = Node::serving_with("header-timeout", &fixed_response_config(), |node| {
        node.timeouts.request_header = Duration::from_millis(200);
    });

    let mut client = TcpStream::connect(node.addr("http")).await.unwrap();
    let received = read_until_closed(&mut client).await;

    assert_eq!(received, "");
    let events = logs.wait_for_events("gfe::conn", 1).await;
    assert_eq!(events[0]["reason"], "header_timeout");
}

/// The proxy's own HTTP/1 keep-alive timer is set a little past
/// `client_idle` (Pingora counts whole seconds), so that it is the edge
/// that closes an idle connection and says why.
#[tokio::test]
async fn an_idle_keep_alive_connection_is_closed_by_the_edge_as_idle() {
    let (logs, _capturing) = CapturedLogs::start();
    let node = Node::serving_with("idle", &fixed_response_config(), |node| {
        node.timeouts.client_idle = Duration::from_millis(1500);
    });
    let mut client = TcpStream::connect(node.addr("http")).await.unwrap();
    client.write_all(REQUEST).await.unwrap();

    let started = Instant::now();
    let received = read_until_closed(&mut client).await;

    assert!(received.starts_with("HTTP/1.1 200"), "{received}");
    assert!(started.elapsed() >= Duration::from_millis(1500));
    let events = logs.wait_for_events("gfe::conn", 1).await;
    assert_eq!(events[0]["reason"], "idle_timeout");
    assert_eq!(events[0]["requests"], 1);
}

#[tokio::test]
async fn serves_a_request_that_takes_longer_than_client_idle() {
    let upstream = spawn_upstream_answering_after(Duration::from_millis(600)).await;
    let node = Node::serving_with("slow-request", &forwarding_config(upstream), |node| {
        node.timeouts.request_header = Duration::from_millis(200);
        node.timeouts.client_idle = Duration::from_millis(200);
    });

    let (status, body) = http_get(node.addr("http"), "a.example.org", "/").await;

    assert_eq!(status, 200, "{body}");
}

/// A backend that holds every request for `/hold` until `release` turns
/// true, counting the requests it holds in `held`, and answers any other
/// at once.
async fn spawn_holding_upstream(
    held: Arc<AtomicUsize>,
    release: watch::Receiver<bool>,
) -> std::net::SocketAddr {
    serve_http1(move |req: http::Request<hyper::body::Incoming>| {
        let (held, mut release) = (Arc::clone(&held), release.clone());
        async move {
            if req.uri().path() == "/hold" {
                held.fetch_add(1, Ordering::SeqCst);
                let _ = release.wait_for(|released| *released).await;
            }
            Response::new(Full::new(Bytes::from("released")))
        }
    })
    .await
}

/// A request for `path` on `sender`, answered with this status.
async fn h2_get(
    mut sender: hyper::client::conn::http2::SendRequest<ChannelBody>,
    path: &str,
) -> http::StatusCode {
    let req = http::Request::builder()
        .uri(format!("http://a.example.org{path}"))
        .body(ChannelBody::full(Bytes::new()))
        .unwrap();
    sender.send_request(req).await.unwrap().status()
}

/// `[limits] max_h2_concurrent_streams` is what an HTTP/2 client is told:
/// beyond it, its streams wait.
#[tokio::test]
async fn an_http2_client_gets_no_more_concurrent_streams_than_the_limit() {
    let held = Arc::new(AtomicUsize::new(0));
    let (release, released) = watch::channel(false);
    let upstream = spawn_holding_upstream(Arc::clone(&held), released).await;
    let node = Node::serving_with("h2-streams", &forwarding_config(upstream), |node| {
        node.limits.max_h2_concurrent_streams = 2;
    });
    let sender = h2_sender(node.addr("http")).await;
    // Once a request has been answered, the client has the server's
    // settings.
    assert_eq!(h2_get(sender.clone(), "/").await, 200);

    let calls: Vec<_> = (0..3)
        .map(|_| tokio::spawn(h2_get(sender.clone(), "/hold")))
        .collect();
    let deadline = Instant::now() + Duration::from_secs(5);
    while held.load(Ordering::SeqCst) < 2 {
        assert!(
            Instant::now() < deadline,
            "the first two streams never arrived"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Absence cannot be polled for: give a third stream the time to show.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(held.load(Ordering::SeqCst), 2);

    release.send_replace(true);
    for call in calls {
        assert_eq!(call.await.unwrap(), 200);
    }
    assert_eq!(held.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn routes_a_request_on_an_ipv4_listener() {
    let node = Node::serving("ipv4", &fixed_response_config());

    let (status, body) = http_get(node.addr("http"), "a.example.org", "/").await;

    assert_eq!((status, body.as_str()), (200, "ok"));
}

/// The proxy finds the connection by the session's addresses, which the
/// edge gives in canonical form: an IPv4 client of a dual-stack listener is
/// `1.2.3.4`, not `::ffff:1.2.3.4`.
#[tokio::test]
async fn routes_a_request_of_an_ipv4_client_on_a_dual_stack_listener() {
    let port = free_port();
    let mut config = fixed_response_config();
    config.listeners = vec![gfe_config::Listener {
        address: "::".parse().unwrap(),
        ..listener("http", ListenProtocol::Http, port)
    }];
    let dir = common::node::scratch("dual-stack");
    common::node::write_config(&dir.join("gfe-dynamic.json"), &config);
    let Ok(node) = Node::boot(dir.clone(), &common::node::bootstrap(&dir), Vec::new()) else {
        println!("skipped: this host cannot listen on [::]");
        return;
    };
    let Ok(_) = TcpStream::connect(("127.0.0.1", port)).await else {
        println!("skipped: [::] does not accept IPv4 clients here (bindv6only)");
        return;
    };

    let (status, body) = http_get(([127, 0, 0, 1], port).into(), "a.example.org", "/").await;

    assert_eq!((status, body.as_str()), (200, "ok"));
    drop(node);
}

#[tokio::test]
async fn drops_connections_beyond_the_node_wide_limit_until_one_closes() {
    let node = Node::serving_with("limit", &fixed_response_config(), |node| {
        node.limits.max_connections = 1;
    });
    let addr = node.addr("http");
    let first = TcpStream::connect(addr).await.unwrap();
    node.wait_for_metric("gfe_connections_active 1").await;

    let mut second = TcpStream::connect(addr).await.unwrap();
    assert_eq!(read_until_closed(&mut second).await, "");
    assert!(node.has_metric(r#"gfe_connections_rejected_total{reason="limit"} 1"#));

    drop(first);
    node.wait_for_metric("gfe_connections_active 0").await;
    let (status, _) = http_get(addr, "a.example.org", "/").await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn the_connection_log_reports_a_finished_connection() {
    let (logs, _capturing) = CapturedLogs::start();
    let node = Node::serving("conn-log", &fixed_response_config());
    let mut client = TcpStream::connect(node.addr("http")).await.unwrap();
    let request = "GET / HTTP/1.1\r\nhost: a.example.org\r\nconnection: close\r\n\r\n";
    client.write_all(request.as_bytes()).await.unwrap();

    let response = read_until_closed(&mut client).await;

    let events = logs.wait_for_events("gfe::conn", 1).await;
    let event = &events[0];
    assert_eq!(event["reason"], "closed");
    assert_eq!(event["listener"], "http");
    assert_eq!(event["proto"], "http");
    assert_eq!(event["client"], "127.0.0.1");
    assert_eq!(event["requests"], 1);
    assert_eq!(event["bytes_in"], request.len());
    assert_eq!(event["bytes_out"], response.len());
    assert!(event["duration_ms"].as_f64().unwrap() > 0.0, "{event}");
    for expected in [
        r#"gfe_connections_closed_total{listener="http",reason="closed"} 1"#.to_string(),
        format!(r#"gfe_bytes_in_total{{listener="http"}} {}"#, request.len()),
        format!(
            r#"gfe_bytes_out_total{{listener="http"}} {}"#,
            response.len()
        ),
    ] {
        node.wait_for_metric(&expected).await;
    }
    node.wait_for_metric("gfe_connections_active 0").await;
}

#[tokio::test]
async fn the_connection_log_has_an_accept_wait_only_with_the_kernel_view() {
    let (logs, _capturing) = CapturedLogs::start();
    let node = Node::serving("accept-wait", &fixed_response_config());
    let mut client = TcpStream::connect(node.addr("http")).await.unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    read_until_closed(&mut client).await;

    let events = logs.wait_for_events("gfe::conn", 1).await;

    let attached = node.has_metric("gfe_ebpf_attached 1");
    assert_eq!(
        events[0]["accept_wait_ms"].is_number(),
        attached,
        "{events:?}"
    );
}

#[tokio::test]
async fn a_config_without_routes_answers_404() {
    let config = DynamicConfig {
        listeners: vec![listener("http", ListenProtocol::Http, 0)],
        ..Default::default()
    };
    let node = Node::serving("no-routes", &config);

    let (status, _) = http_get(node.addr("http"), "a.example.org", "/").await;

    assert_eq!(status, 404);
}

/// An idle HTTP/2 connection is asked to leave by the edge (`GOAWAY`) at
/// `client_idle`, and says why: the proxy runs no idle timer of its own,
/// which would drop the connection without a `GOAWAY` and log it `closed`.
#[tokio::test]
async fn an_idle_http2_connection_is_sent_goaway_and_logged_as_idle() {
    let (logs, _capturing) = CapturedLogs::start();
    let node = Node::serving_with("h2-idle", &fixed_response_config(), |node| {
        node.timeouts.client_idle = Duration::from_millis(500);
    });
    let stream = TcpStream::connect(node.addr("http")).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .unwrap();
    let connection = tokio::spawn(conn);
    let req = http::Request::builder()
        .uri("http://a.example.org/")
        .body(ChannelBody::full(Bytes::new()))
        .unwrap();
    assert_eq!(sender.send_request(req).await.unwrap().status(), 200);

    let started = Instant::now();
    let ended = tokio::time::timeout(Duration::from_secs(5), connection)
        .await
        .expect("the idle connection should be closed");

    // A GOAWAY ends the client's connection cleanly.
    ended.unwrap().unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(400),
        "{:?}",
        started.elapsed()
    );
    let events = logs.wait_for_events("gfe::conn", 1).await;
    assert_eq!(events[0]["reason"], "idle_timeout", "{events:?}");
    assert_eq!(events[0]["requests"], 1);
}
