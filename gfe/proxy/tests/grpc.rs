//! gRPC end to end: calls of every shape relayed message by message with
//! their trailers, to `h2c` and `https` pools, and calls GFE fails itself
//! answered in gRPC's terms.

mod common;

use common::*;
use gfe_config::Scheme;
use hyper::body::Frame;
use hyper::{Request, Response};
use netkit_http::Bytes;
use std::time::Duration;

/// [`grpc_config`] for an `https` backend trusted by `ca_pem`.
async fn https_grpc_proxy() -> (Proxy, std::net::SocketAddr) {
    let (upstream, ca_pem) = spawn_tls_upstream("127.0.0.1", ClientAuth::None).await;
    let mut cfg = grpc_config(upstream);
    cfg.pools[0].scheme = Scheme::Https;
    let mut node = node_config();
    node.upstream.extra_ca_file = Some(pem_file(&ca_pem));
    (Proxy::start_with(&cfg, node, None).await, upstream)
}

#[tokio::test]
async fn relays_a_unary_call_with_its_trailers_to_an_h2c_pool() {
    let proxy = Proxy::start(&grpc_config(spawn_grpc_upstream().await)).await;

    let mut call = GrpcCall::open(proxy.addr).await;
    call.send("ping").await;
    assert_eq!(call.response.status(), 200);
    assert_eq!(call.next_message().await, "ping");
    let trailers = call.finish().await;

    assert_eq!(trailers["grpc-status"], "0");
}

#[tokio::test]
async fn relays_a_unary_call_with_its_trailers_to_an_https_pool() {
    let (proxy, _) = https_grpc_proxy().await;

    let mut call = GrpcCall::open(proxy.addr).await;
    call.send("ping").await;
    assert_eq!(call.response.status(), 200);
    assert_eq!(call.next_message().await, "ping");
    let trailers = call.finish().await;

    assert_eq!(trailers["grpc-status"], "0");
}

/// gRPC servers use `te: trailers` to detect proxies that cannot relay
/// trailers, and reject calls that arrive without it.
#[tokio::test]
async fn forwards_te_trailers_to_the_backend() {
    let proxy = Proxy::start(&grpc_config(spawn_grpc_upstream().await)).await;

    let call = GrpcCall::open(proxy.addr).await;

    assert_eq!(call.response.headers()["x-seen-te"], "trailers");
}

/// Each reply is awaited before the next message is sent, with the request
/// stream still open: anything buffered until end-of-stream would stall.
#[tokio::test]
async fn relays_a_bidirectional_stream_message_by_message() {
    for https in [false, true] {
        let proxy = if https {
            https_grpc_proxy().await.0
        } else {
            Proxy::start(&grpc_config(spawn_grpc_upstream().await)).await
        };

        let mut call = GrpcCall::open(proxy.addr).await;
        call.send("one").await;
        assert_eq!(call.next_message().await, "one", "https: {https}");
        call.send("two").await;
        assert_eq!(call.next_message().await, "two", "https: {https}");
        let trailers = call.finish().await;

        assert_eq!(trailers["grpc-status"], "0");
    }
}

#[tokio::test]
async fn relays_a_client_streaming_call() {
    // The backend answers once, with how many messages it was sent.
    let upstream = serve_h2c(|req: Request<hyper::body::Incoming>| async move {
        use http_body_util::BodyExt;
        let mut body = req.into_body();
        let mut messages = 0;
        while let Some(Ok(frame)) = body.frame().await {
            if frame.data_ref().is_some_and(|data| !data.is_empty()) {
                messages += 1;
            }
        }
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        tx.send(Frame::data(Bytes::from(format!("{messages} messages"))))
            .await
            .unwrap();
        let mut trailers = netkit_http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        tx.send(Frame::trailers(trailers)).await.unwrap();
        Response::builder()
            .header("content-type", "application/grpc")
            .body(ChannelBody(rx))
            .unwrap()
    })
    .await;
    let proxy = Proxy::start(&grpc_config(upstream)).await;

    let mut sender = h2_sender(proxy.addr).await;
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let req = Request::builder()
        .method("POST")
        .uri("http://grpc.example.org/echo.Echo/Count")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(ChannelBody(rx))
        .unwrap();
    let responding = tokio::spawn(async move { sender.send_request(req).await.unwrap() });
    for message in ["a", "b", "c"] {
        tx.send(Frame::data(Bytes::from(message))).await.unwrap();
    }
    drop(tx);
    let mut call = GrpcCall {
        request: tokio::sync::mpsc::channel(1).0,
        response: responding.await.unwrap(),
    };

    assert_eq!(call.next_message().await, "3 messages");
    assert_eq!(call.finish().await["grpc-status"], "0");
}

#[tokio::test]
async fn relays_a_server_streaming_call() {
    let upstream = serve_h2c(|_req: Request<hyper::body::Incoming>| async {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            for message in ["one", "two", "three"] {
                tx.send(Frame::data(Bytes::from(message))).await.unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let mut trailers = netkit_http::HeaderMap::new();
            trailers.insert("grpc-status", "0".parse().unwrap());
            tx.send(Frame::trailers(trailers)).await.unwrap();
        });
        Response::builder()
            .header("content-type", "application/grpc")
            .body(ChannelBody(rx))
            .unwrap()
    })
    .await;
    let proxy = Proxy::start(&grpc_config(upstream)).await;

    let mut call = GrpcCall::open(proxy.addr).await;
    call.send("subscribe").await;

    for expected in ["one", "two", "three"] {
        assert_eq!(call.next_message().await, expected);
    }
    assert_eq!(call.finish().await["grpc-status"], "0");
}

#[tokio::test]
async fn access_log_and_metrics_report_the_grpc_status() {
    let (logs, _guard) = CapturedLogs::start();
    let proxy = Proxy::start(&grpc_config(spawn_grpc_upstream().await)).await;

    let mut call = GrpcCall::open(proxy.addr).await;
    call.send("ping").await;
    call.next_message().await;
    call.finish().await;
    let event = logs.access_event().await;

    assert_eq!(event["grpc_status"], 0);
    assert_eq!(event["termination"], "complete");
    proxy
        .wait_for_metric(
            r#"gfe_grpc_responses_total{listener="http",vhost="*",route="grpc",grpc_status="0"} 1"#,
        )
        .await;
}

/// A streaming call may legitimately have nothing to send, not even headers,
/// for a long time. It is bounded by the deadline its client sets, not by the
/// timeouts meant for request/response exchanges.
#[tokio::test]
async fn a_call_silent_longer_than_upstream_first_byte_is_not_cut() {
    let upstream = spawn_grpc_upstream_answering_after(Duration::from_millis(700)).await;
    let mut node = node_config();
    node.timeouts.upstream_first_byte = Duration::from_millis(200);
    let proxy = Proxy::start_with(&grpc_config(upstream), node, None).await;

    let mut call = GrpcCall::open(proxy.addr).await;
    call.send("late").await;

    assert_eq!(call.response.status(), 200);
    assert_eq!(call.response.headers()["content-type"], "application/grpc");
    assert_eq!(call.next_message().await, "late");
}

#[tokio::test]
async fn fails_a_call_without_a_route_with_unimplemented() {
    let (logs, _guard) = CapturedLogs::start();
    let mut cfg = grpc_config(spawn_grpc_upstream().await);
    cfg.routes[0].host = "elsewhere.example.org".into();
    let proxy = Proxy::start(&cfg).await;

    let call = GrpcCall::open(proxy.addr).await;
    let event = logs.access_event().await;

    let headers = call.response.headers();
    assert_eq!(call.response.status(), 200);
    assert_eq!(headers["grpc-status"], "12");
    assert_eq!(headers["grpc-message"], "gfe: no_route");
    assert_eq!(event["grpc_status"], 12);
    assert_eq!(event["status"], 200);
    assert_eq!(event["error"], "no_route");
    proxy
        .wait_for_metric(
            r#"gfe_grpc_responses_total{listener="http",vhost="none",route="none",grpc_status="12"} 1"#,
        )
        .await;
}

#[tokio::test]
async fn fails_a_call_to_an_unreachable_backend_with_unavailable() {
    let (logs, _guard) = CapturedLogs::start();
    let proxy = Proxy::start(&grpc_config(closed_port())).await;

    let mut call = GrpcCall::open(proxy.addr).await;
    let event = logs.access_event().await;

    let headers = call.response.headers().clone();
    assert_eq!(call.response.status(), 200);
    assert_eq!(headers["content-type"], "application/grpc");
    assert_eq!(headers["grpc-status"], "14");
    let message = headers["grpc-message"].to_str().unwrap();
    assert!(message.contains("upstream_connect_refused"), "{message}");
    assert_eq!(event["grpc_status"], 14);
    assert_eq!(event["error"], "upstream_connect_refused");
    // Trailers-only: the headers end the stream.
    let end = tokio::time::timeout(
        Duration::from_secs(5),
        http_body_util::BodyExt::frame(call.response.body_mut()),
    )
    .await
    .unwrap();
    assert!(end.is_none(), "{end:?}");
}

#[tokio::test]
async fn fails_a_call_with_no_healthy_backend_with_unavailable() {
    let upstream = spawn_grpc_upstream().await;
    let proxy = Proxy::start(&grpc_config(upstream)).await;
    proxy.state.health().set(
        &upstream.ip().to_string(),
        upstream.port(),
        netkit_health_checking::HealthStatus::Unhealthy,
    );

    let call = GrpcCall::open(proxy.addr).await;

    assert_eq!(call.response.status(), 200);
    assert_eq!(call.response.headers()["grpc-status"], "14");
    assert_eq!(
        call.response.headers()["grpc-message"],
        "gfe: no_healthy_upstream"
    );
}

#[tokio::test]
async fn fails_a_call_to_a_pool_with_max_in_flight_calls_as_unavailable() {
    let mut cfg = grpc_config(spawn_grpc_upstream().await);
    cfg.pools[0].max_in_flight = std::num::NonZeroU32::new(1);
    let proxy = Proxy::start(&cfg).await;

    // The first call stays open, and in flight, while the second is made.
    let first = GrpcCall::open(proxy.addr).await;
    let second = GrpcCall::open(proxy.addr).await;

    assert_eq!(first.response.headers().get("grpc-status"), None);
    let message = second.response.headers()["grpc-message"].to_str().unwrap();
    assert_eq!(second.response.headers()["grpc-status"], "14");
    assert!(message.contains("upstream_pool_full"), "{message}");
}

#[tokio::test]
async fn fails_a_call_to_a_pool_over_its_rate_as_unavailable() {
    let mut cfg = grpc_config(spawn_grpc_upstream().await);
    cfg.pools[0].max_requests_per_second = std::num::NonZeroU32::new(1);
    let proxy = Proxy::start(&cfg).await;

    let first = GrpcCall::open(proxy.addr).await;
    let second = GrpcCall::open(proxy.addr).await;

    assert_eq!(first.response.headers().get("grpc-status"), None);
    let message = second.response.headers()["grpc-message"].to_str().unwrap();
    assert_eq!(second.response.headers()["grpc-status"], "14");
    assert!(message.contains("upstream_pool_rate_limited"), "{message}");
}

/// A backend is busy with a call until its response has been relayed to
/// the end, not merely until the response headers arrive.
#[tokio::test]
async fn backend_stays_in_flight_for_the_whole_response() {
    let (logs, _guard) = CapturedLogs::start();
    let upstream = spawn_grpc_upstream().await;
    let proxy = Proxy::start(&grpc_config(upstream)).await;
    let in_flight = |n: u8| {
        format!(r#"gfe_upstream_requests_in_flight{{pool="grpc",backend="{upstream}"}} {n}"#)
    };

    let mut call = GrpcCall::open(proxy.addr).await;
    call.send("one").await;
    call.next_message().await;
    let during = proxy.metrics();
    call.finish().await;
    logs.access_event().await;

    assert!(during.contains(&in_flight(1)), "{during}");
    proxy.wait_for_metric(&in_flight(0)).await;
}

/// The whole way a gRPC call takes on a node: TLS terminated at the edge
/// (HTTP/2 by ALPN), the call relayed message by message to an `https`
/// backend over HTTP/2, and the trailers back.
#[tokio::test]
async fn relays_a_call_through_tls_termination_to_an_https_backend() {
    use common::node::{Node, tls_client, tls_connect};
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let (upstream, ca_pem) = spawn_tls_upstream("127.0.0.1", ClientAuth::None).await;
    let (cert_file, key_file, cert) = certificate_files(&["grpc.example.org"]);
    let mut config = grpc_config(upstream);
    config.pools[0].scheme = Scheme::Https;
    config.listeners[0].protocol = gfe_config::ListenProtocol::Https;
    config.certificates = vec![gfe_config::CertEntry {
        sni: vec!["grpc.example.org".into()],
        default: true,
        cert_file,
        key_file,
    }];
    let node = Node::serving_with("grpc-tls", &config, |node| {
        node.upstream.extra_ca_file = Some(pem_file(&ca_pem));
    });
    let client = tls_client(
        &[cert.cert.der().clone()],
        rustls::DEFAULT_VERSIONS,
        &[b"h2"],
    );
    let stream = tls_connect(&client, node.addr("http"), "grpc.example.org")
        .await
        .unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(conn);
    let (request, rx) = tokio::sync::mpsc::channel(1);
    let req = Request::builder()
        .method("POST")
        .uri("https://grpc.example.org/echo.Echo/Stream")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(ChannelBody(rx))
        .unwrap();
    let response = sender.send_request(req).await.unwrap();
    let mut call = GrpcCall { request, response };

    call.send("ping").await;
    assert_eq!(call.next_message().await, "ping");
    call.send("pong").await;
    assert_eq!(call.next_message().await, "pong");
    let trailers = call.finish().await;

    assert_eq!(trailers["grpc-status"], "0");
    node.wait_for_metric(
        r#"gfe_grpc_responses_total{listener="http",vhost="*",route="grpc",grpc_status="0"} 1"#,
    )
    .await;
}
