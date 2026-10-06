//! How long GFE waits for a backend, and for a client sending its body.

mod common;

use common::*;
use http_body_util::{BodyExt, Full};
use netkit_http::Bytes;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A node config whose backends must start answering within `first_byte`.
fn first_byte(first_byte: Duration) -> gfe_config::NodeConfig {
    let mut node = node_config();
    node.timeouts.upstream_first_byte = first_byte;
    node
}

/// A backend that never answers the TCP handshake within `upstream_connect`,
/// if the host has a route to TEST-NET-1; a host without one fails the
/// connect at once.
#[tokio::test]
async fn gives_up_connecting_after_upstream_connect() {
    let (logs, _guard) = CapturedLogs::start();
    let mut node = node_config();
    node.timeouts.upstream_connect = Duration::from_millis(200);
    let unroutable: SocketAddr = "192.0.2.1:80".parse().unwrap();
    let proxy = Proxy::start_with(&forwarding_config(unroutable), node, None).await;

    let started = Instant::now();
    let (status, _) = http_get(proxy.addr, "a.example.org", "/").await;
    let event = logs.access_event().await;

    assert_eq!(status, 502);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    let error = event["error"].as_str().unwrap();
    assert!(
        ["upstream_connect_timeout", "upstream_connect_error"].contains(&error),
        "{event}"
    );
}

#[tokio::test]
async fn gives_up_on_a_backend_silent_for_upstream_first_byte() {
    let (logs, _guard) = CapturedLogs::start();
    let upstream = spawn_silent_upstream().await;
    let proxy = Proxy::start_with(
        &forwarding_config(upstream),
        first_byte(Duration::from_millis(200)),
        None,
    )
    .await;

    let started = Instant::now();
    let (status, body) = http_get(proxy.addr, "a.example.org", "/").await;
    let event = logs.access_event().await;

    assert_eq!(status, 504);
    assert!(body.starts_with("504 upstream timeout"), "{body}");
    assert_eq!(event["error"], "upstream_timeout");
    // A timeout is not retried.
    assert_eq!(event["attempts"], 1);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    proxy
        .wait_for_metric(&format!(
            r#"gfe_upstream_errors_total{{pool="pool",backend="{upstream}",kind="timeout"}} 1"#
        ))
        .await;
}

#[tokio::test]
async fn upload_slower_than_upstream_first_byte_succeeds_while_it_progresses() {
    let proxy = Proxy::start_with(
        &forwarding_config(spawn_upload_upstream().await),
        first_byte(Duration::from_millis(300)),
        None,
    )
    .await;

    // 10 bytes every 100 ms: one second in total, three times the timeout.
    let mut stream = TcpStream::connect(proxy.addr).await.unwrap();
    let head = "POST /upload HTTP/1.1\r\nhost: a.example.org\r\ncontent-length: 100\r\nconnection: close\r\n\r\n";
    stream.write_all(head.as_bytes()).await.unwrap();
    for _ in 0..10 {
        stream.write_all(b"0123456789").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let response = read_until_closed(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("received 100"), "{response}");
}

/// A backend that answers a request with half of its body, then stalls for
/// `stall` before it sends the other half.
async fn spawn_upstream_stalling_mid_body(stall: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nfirst")
                    .await;
                tokio::time::sleep(stall).await;
                let _ = stream.write_all(b"-last").await;
            });
        }
    });
    addr
}

/// `upstream_first_byte` bounds the wait for a response to start; one that
/// has started is relayed to its end, however long it pauses.
#[tokio::test]
async fn a_response_that_has_started_is_not_cut_by_upstream_first_byte() {
    let upstream = spawn_upstream_stalling_mid_body(Duration::from_millis(600)).await;
    let proxy = Proxy::start_with(
        &forwarding_config(upstream),
        first_byte(Duration::from_millis(200)),
        None,
    )
    .await;

    let (status, body) = http_get(proxy.addr, "a.example.org", "/").await;

    assert_eq!((status, body.as_str()), (200, "first-last"));
}

/// The same upload to an `h2c` pool: HTTP/2 to the backend changes nothing
/// to how the wait for its answer is bounded.
#[tokio::test]
async fn upload_to_an_h2c_pool_slower_than_upstream_first_byte_succeeds_while_it_progresses() {
    let upstream = serve_h2c(|req: hyper::Request<hyper::body::Incoming>| async move {
        let received = req.into_body().collect().await.unwrap().to_bytes();
        hyper::Response::new(Full::new(Bytes::from(format!(
            "received {}",
            received.len()
        ))))
    })
    .await;
    let mut config = forwarding_config(upstream);
    config.pools[0] = pool("pool", gfe_config::Scheme::H2c, &[upstream]);
    let proxy = Proxy::start_with(&config, first_byte(Duration::from_millis(300)), None).await;

    // 10 bytes every 100 ms: one second in total, three times the timeout.
    let mut stream = TcpStream::connect(proxy.addr).await.unwrap();
    let head = "POST /upload HTTP/1.1\r\nhost: a.example.org\r\ncontent-length: 100\r\nconnection: close\r\n\r\n";
    stream.write_all(head.as_bytes()).await.unwrap();
    for _ in 0..10 {
        stream.write_all(b"0123456789").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let response = read_until_closed(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("received 100"), "{response}");
}

/// When the upload itself stalls, the client is the one at fault: it gets a
/// 408 and the backend is not counted as having failed.
#[tokio::test]
async fn stalled_upload_is_answered_with_408() {
    let (logs, _guard) = CapturedLogs::start();
    let proxy = Proxy::start_with(
        &forwarding_config(spawn_upload_upstream().await),
        first_byte(Duration::from_millis(200)),
        None,
    )
    .await;

    let mut stream = TcpStream::connect(proxy.addr).await.unwrap();
    let head = "POST /upload HTTP/1.1\r\nhost: a.example.org\r\ncontent-length: 100\r\n\r\n";
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(b"0123456789").await.unwrap();
    let response = read_until_closed(&mut stream).await;
    let event = logs.access_event().await;

    assert!(response.starts_with("HTTP/1.1 408"), "{response}");
    assert_eq!(event["error"], "request_body_timeout");
    let metrics = proxy.metrics();
    assert!(!metrics.contains("gfe_upstream_errors_total{"), "{metrics}");
}

/// When it is the backend that stops taking the upload, the client is not
/// to blame: it gets a 504 and the backend is counted as having timed out.
#[tokio::test]
async fn backend_that_stops_reading_an_upload_is_answered_with_504() {
    let (logs, _guard) = CapturedLogs::start();
    let upstream = spawn_upstream_not_reading_the_body().await;
    let proxy = Proxy::start_with(
        &forwarding_config(upstream),
        first_byte(Duration::from_millis(300)),
        None,
    )
    .await;

    // More than every buffer between client and backend can hold, sent as
    // fast as it is taken.
    let total: usize = 64 * 1024 * 1024;
    let (mut from_proxy, mut to_proxy) = TcpStream::connect(proxy.addr).await.unwrap().into_split();
    let head =
        format!("POST /upload HTTP/1.1\r\nhost: a.example.org\r\ncontent-length: {total}\r\n\r\n");
    tokio::spawn(async move {
        to_proxy.write_all(head.as_bytes()).await.unwrap();
        let chunk = vec![b'x'; 64 * 1024];
        for _ in 0..total / chunk.len() {
            if to_proxy.write_all(&chunk).await.is_err() {
                return;
            }
        }
    });
    let mut status_line = [0u8; 12];
    tokio::time::timeout(
        Duration::from_secs(10),
        from_proxy.read_exact(&mut status_line),
    )
    .await
    .expect("a response should arrive")
    .unwrap();
    let event = logs.access_event().await;

    assert_eq!(String::from_utf8_lossy(&status_line), "HTTP/1.1 504");
    assert_eq!(event["error"], "upstream_timeout");
    proxy
        .wait_for_metric(&format!(
            r#"gfe_upstream_errors_total{{pool="pool",backend="{upstream}",kind="timeout"}} 1"#
        ))
        .await;
}

/// A backend that reads a request and closes the connection `after` it,
/// without answering.
async fn spawn_upstream_closing_after(after: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                tokio::time::sleep(after).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn no_retry_is_started_once_request_total_has_passed() {
    let (logs, _guard) = CapturedLogs::start();
    let mut node = node_config();
    node.timeouts.request_total = Duration::from_millis(200);
    let upstream = spawn_upstream_closing_after(Duration::from_millis(400)).await;
    let proxy = Proxy::start_with(&forwarding_config(upstream), node, None).await;

    let (status, _) = http_get(proxy.addr, "a.example.org", "/").await;
    let event = logs.access_event().await;

    assert_eq!(status, 504);
    assert_eq!(event["error"], "upstream_timeout");
    assert_eq!(event["attempts"], 1);
}

#[tokio::test]
async fn a_failure_within_request_total_is_retried() {
    let (logs, _guard) = CapturedLogs::start();
    let upstream = spawn_upstream_closing_after(Duration::from_millis(50)).await;
    let proxy = Proxy::start(&forwarding_config(upstream)).await;

    let (status, _) = http_get(proxy.addr, "a.example.org", "/").await;
    let event = logs.access_event().await;

    assert_eq!(status, 502);
    assert_eq!(event["error"], "upstream_reset");
    assert_eq!(event["attempts"], 2);
}
