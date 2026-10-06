//! What is counted and logged about a request, whatever happens to it:
//! exactly one `gfe::access` event and one count.

mod common;

use common::*;
use gfe_config::RouteAction;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use netkit_http::Bytes;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const WEB: &str = r#"listener="http",vhost="a.example.org",route="web""#;

#[tokio::test]
async fn access_log_describes_a_proxied_request() {
    let (logs, _guard) = CapturedLogs::start();
    let upstream = spawn_upstream().await;
    let proxy = Proxy::start(&forwarding_config(upstream)).await;

    let answer = get_with(
        proxy.addr,
        "a.example.org",
        "/some/path?q=1",
        &[("user-agent", "tests/1.0"), ("x-request-id", "abc")],
    )
    .await;
    let event = logs.access_event().await;

    assert_eq!(event["request_id"], "abc");
    assert_eq!(event["status"], 200);
    assert_eq!(event["method"], "GET");
    assert_eq!(event["host"], "a.example.org");
    assert_eq!(event["path"], "/some/path");
    assert_eq!(event["user_agent"], "tests/1.0");
    assert_eq!(event["http_version"], "HTTP/1.1");
    assert_eq!(event["client"], "127.0.0.1");
    assert!(event["client_port"].as_u64().unwrap() > 0, "{event}");
    assert_eq!(event["listener"], "http");
    assert_eq!(event["proto"], "http");
    assert_eq!(event["route"], "web");
    assert_eq!(event["pool"], "pool");
    assert_eq!(event["backend"], upstream.to_string());
    assert_eq!(event["attempts"], 1);
    assert_eq!(event["termination"], "complete");
    assert_eq!(event["request_bytes"], 0);
    assert_eq!(event["response_bytes"], answer.body.len());
    assert!(event["error"].is_null(), "{event}");
    assert!(event["grpc_status"].is_null(), "{event}");
    assert!(event["sni"].is_null(), "{event}");
    assert!(event["duration_ms"].as_f64().unwrap() > 0.0, "{event}");
    assert!(event["upstream_ttfb_ms"].as_f64().unwrap() > 0.0, "{event}");
    proxy
        .wait_for_metric(&format!(r#"gfe_requests_total{{{WEB},status="200"}} 1"#))
        .await;
    proxy
        .wait_for_metric(&format!(
            r#"gfe_upstream_requests_total{{pool="pool",backend="{upstream}",status="200"}} 1"#
        ))
        .await;
    proxy
        .wait_for_metric(&format!(
            r#"gfe_upstream_request_duration_seconds_count{{pool="pool",backend="{upstream}"}} 1"#
        ))
        .await;
    logs.assert_no_more_than(1).await;
}

#[tokio::test]
async fn access_log_reports_the_tls_parameters_of_the_connection() {
    let (logs, _guard) = CapturedLogs::start();
    let proxy = Proxy::start_with(
        &fixed_response_config(),
        node_config(),
        Some(tls_info("a.example.org")),
    )
    .await;

    http_get(proxy.addr, "a.example.org", "/").await;
    let event = logs.access_event().await;

    assert_eq!(event["proto"], "https");
    assert_eq!(event["sni"], "a.example.org");
    assert_eq!(event["tls_version"], "TLSv1.3");
    assert_eq!(event["tls_cipher"], "TLS13_AES_256_GCM_SHA384");
}

#[tokio::test]
async fn access_log_and_metrics_count_body_bytes() {
    let (logs, _guard) = CapturedLogs::start();
    let proxy = Proxy::start(&forwarding_config(spawn_upload_upstream().await)).await;

    let mut sender = h1_sender(proxy.addr).await;
    let req = Request::builder()
        .method("POST")
        .uri("/upload")
        .header("host", "a.example.org")
        .body(Full::new(Bytes::from(vec![b'x'; 1000])))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let event = logs.access_event().await;

    assert_eq!(event["request_bytes"], 1000);
    assert_eq!(event["response_bytes"], body.len());
    proxy
        .wait_for_metric(&format!("gfe_request_body_bytes_total{{{WEB}}} 1000"))
        .await;
    proxy
        .wait_for_metric(&format!(
            "gfe_response_body_bytes_total{{{WEB}}} {}",
            body.len()
        ))
        .await;
    proxy.wait_for_metric("gfe_requests_in_flight 0").await;
}

#[tokio::test]
async fn access_log_reports_a_failure_gfe_answered() {
    let (logs, _guard) = CapturedLogs::start();
    let mut cfg = forwarding_config(spawn_upstream().await);
    cfg.routes[0].action = RouteAction::Forward("missing".into());
    let proxy = Proxy::start(&cfg).await;

    let (status, body) = http_get(proxy.addr, "a.example.org", "/").await;
    let event = logs.access_event().await;

    assert_eq!(status, 502);
    assert!(body.starts_with("502 pool not found"), "{body}");
    assert_eq!(event["error"], "pool_not_found");
    assert_eq!(event["termination"], "complete");
    assert_eq!(event["response_bytes"], body.len());
    proxy
        .wait_for_metric(&format!(r#"gfe_requests_total{{{WEB},status="502"}} 1"#))
        .await;
    logs.assert_no_more_than(1).await;
}

#[tokio::test]
async fn access_log_reports_why_the_upstream_could_not_be_reached() {
    let (logs, _guard) = CapturedLogs::start();
    let dead = closed_port();
    let proxy = Proxy::start(&forwarding_config(dead)).await;

    let (status, _) = http_get(proxy.addr, "a.example.org", "/").await;
    let event = logs.access_event().await;

    assert_eq!(status, 502);
    assert_eq!(event["error"], "upstream_connect_refused");
    assert_eq!(event["backend"], dead.to_string());
    assert_eq!(event["termination"], "complete");
    proxy
        .wait_for_metric(&format!(
            r#"gfe_upstream_requests_total{{pool="pool",backend="{dead}",status="502"}} 2"#
        ))
        .await;
    logs.assert_no_more_than(1).await;
}

/// A client that gives up while GFE is still waiting for the upstream never
/// receives a status. It is logged as 499, the convention nginx established.
#[tokio::test]
async fn logs_a_request_abandoned_before_the_response_as_499() {
    let (logs, _guard) = CapturedLogs::start();
    let upstream = spawn_upstream_answering_after(Duration::from_secs(3)).await;
    let proxy = Proxy::start(&forwarding_config(upstream)).await;

    let mut stream = TcpStream::connect(proxy.addr).await.unwrap();
    stream
        .write_all(b"GET /slow HTTP/1.1\r\nhost: a.example.org\r\n\r\n")
        .await
        .unwrap();
    proxy
        .wait_for_metric(&format!(
            r#"gfe_upstream_requests_in_flight{{pool="pool",backend="{upstream}"}} 1"#
        ))
        .await;
    drop(stream);
    let event = logs.access_event().await;

    assert_eq!(event["status"], 499);
    assert_eq!(event["termination"], "client_abort");
    assert_eq!(event["path"], "/slow");
    assert!(event["error"].is_null(), "{event}");
    proxy
        .wait_for_metric(&format!(
            r#"gfe_requests_aborted_total{{{WEB},by="client"}} 1"#
        ))
        .await;
    proxy
        .wait_for_metric(&format!(r#"gfe_requests_total{{{WEB},status="499"}} 1"#))
        .await;
    proxy
        .wait_for_metric(&format!(
            r#"gfe_upstream_requests_in_flight{{pool="pool",backend="{upstream}"}} 0"#
        ))
        .await;
    proxy.wait_for_metric("gfe_requests_in_flight 0").await;
    logs.assert_no_more_than(1).await;
}

#[tokio::test]
async fn logs_a_client_abort_in_the_middle_of_a_response() {
    let (logs, _guard) = CapturedLogs::start();
    let proxy = Proxy::start(&grpc_config(spawn_grpc_upstream().await)).await;

    // The stream is open and has delivered a message when the client leaves.
    let mut call = GrpcCall::open(proxy.addr).await;
    call.send("one").await;
    assert_eq!(call.next_message().await, "one");
    drop(call);
    let event = logs.access_event().await;

    assert_eq!(event["status"], 200);
    assert_eq!(event["termination"], "client_abort");
    assert_eq!(event["response_bytes"], 3);
    assert_eq!(event["request_bytes"], 3);
    proxy
        .wait_for_metric(
            r#"gfe_requests_aborted_total{listener="http",vhost="*",route="grpc",by="client"} 1"#,
        )
        .await;
    logs.assert_no_more_than(1).await;
}

/// A backend that sends response headers and part of the body, then closes.
async fn spawn_upstream_dying_mid_body() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\npartial")
                    .await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn logs_a_backend_that_dies_mid_body_as_an_upstream_abort() {
    let (logs, _guard) = CapturedLogs::start();
    let proxy = Proxy::start(&forwarding_config(spawn_upstream_dying_mid_body().await)).await;

    let response = raw_exchange(
        proxy.addr,
        "GET / HTTP/1.1\r\nhost: a.example.org\r\nconnection: close\r\n\r\n",
    )
    .await;
    let event = logs.access_event().await;

    assert!(response.ends_with("partial"), "{response}");
    assert_eq!(event["status"], 200);
    assert_eq!(event["termination"], "upstream_abort");
    assert_eq!(event["response_bytes"], 7);
    proxy
        .wait_for_metric(&format!(
            r#"gfe_requests_aborted_total{{{WEB},by="upstream"}} 1"#
        ))
        .await;
    proxy
        .wait_for_metric(&format!(r#"gfe_requests_total{{{WEB},status="200"}} 1"#))
        .await;
    logs.assert_no_more_than(1).await;
}

#[tokio::test]
async fn counts_every_request_of_a_keep_alive_connection_once() {
    let (logs, _guard) = CapturedLogs::start();
    let proxy = Proxy::start(&forwarding_config(spawn_upstream().await)).await;
    let mut sender = h1_sender(proxy.addr).await;

    for path in ["/one", "/two", "/three"] {
        let req = Request::builder()
            .uri(path)
            .header("host", "a.example.org")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();
        collect(sender.send_request(req).await.unwrap()).await;
    }

    for path in ["/one", "/two", "/three"] {
        logs.access_event_for(path).await;
    }
    proxy
        .wait_for_metric(&format!(r#"gfe_requests_total{{{WEB},status="200"}} 3"#))
        .await;
    logs.assert_no_more_than(3).await;
}

/// The connection event and the access events of one TLS connection
/// through a whole front end tell the same story: the same client,
/// listener and TLS parameters, as many requests as access events, and at
/// least as many bytes on the wire as in the bodies.
#[tokio::test]
async fn connection_and_access_events_of_a_connection_agree() {
    use common::node::{Node, h1_tls_client, tls_connect};
    use hyper_util::rt::TokioIo;

    let (logs, _guard) = CapturedLogs::start();
    let upstream = spawn_upload_upstream().await;
    let (cert_file, key_file, cert) = certificate_files(&["a.example.org"]);
    let mut config = forwarding_config(upstream);
    config.listeners[0].protocol = gfe_config::ListenProtocol::Https;
    config.certificates = vec![gfe_config::CertEntry {
        sni: vec!["a.example.org".into()],
        default: false,
        cert_file,
        key_file,
    }];
    let node = Node::serving("events-agree", &config);
    let stream = tls_connect(
        &h1_tls_client(&[cert.cert.der().clone()]),
        node.addr("http"),
        "a.example.org",
    )
    .await
    .unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let connection = tokio::spawn(conn);

    for size in [10, 1000, 100_000] {
        let req = Request::builder()
            .method("POST")
            .uri(format!("/upload/{size}"))
            .header("host", "a.example.org")
            .body(Full::new(Bytes::from(vec![b'x'; size])))
            .unwrap();
        let answer = collect(sender.send_request(req).await.unwrap()).await;
        assert_eq!(answer.body, format!("received {size}"));
    }
    drop(sender);
    connection.await.unwrap().unwrap();

    let conn = logs.wait_for_events("gfe::conn", 1).await.remove(0);
    let access = logs.access_events();
    assert_eq!(access.len(), 3, "{access:?}");
    assert_eq!(conn["requests"], 3, "{conn}");
    for event in &access {
        for field in [
            "client",
            "client_port",
            "listener",
            "sni",
            "tls_version",
            "tls_cipher",
        ] {
            assert_eq!(event[field], conn[field], "{field}: {event} {conn}");
        }
        assert_eq!(event["proto"], "https");
    }
    let total = |field: &str| -> u64 {
        access
            .iter()
            .map(|event| event[field].as_u64().unwrap())
            .sum()
    };
    assert_eq!(total("request_bytes"), 101_010);
    assert!(
        conn["bytes_in"].as_u64().unwrap() > total("request_bytes"),
        "{conn}"
    );
    assert!(
        conn["bytes_out"].as_u64().unwrap() > total("response_bytes"),
        "{conn}"
    );
}
