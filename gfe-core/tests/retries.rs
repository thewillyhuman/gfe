//! What is retried: a bodyless idempotent request, once, against a new
//! selection, before any response; nothing else.

mod common;

use common::*;
use gfe_config::Scheme;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A proxy whose pool's first backend refuses connections and whose second
/// one answers. Round robin starts with the first.
async fn proxy_with_a_dead_first_backend(upstream: SocketAddr) -> (Proxy, SocketAddr) {
    let dead = closed_port();
    let mut cfg = forwarding_config(upstream);
    cfg.pools[0] = pool("pool", Scheme::Http, &[dead, upstream]);
    (Proxy::start(&cfg).await, dead)
}

#[tokio::test]
async fn retries_a_bodyless_get_against_another_backend() {
    let (logs, _guard) = CapturedLogs::start();
    let upstream = spawn_upstream().await;
    let (proxy, dead) = proxy_with_a_dead_first_backend(upstream).await;

    let (status, body) = http_get(proxy.addr, "a.example.org", "/").await;
    let event = logs.access_event().await;

    assert_eq!(status, 200, "{body}");
    assert_eq!(event["attempts"], 2);
    assert_eq!(event["backend"], upstream.to_string());
    assert!(event["error"].is_null(), "{event}");
    proxy
        .wait_for_metric(r#"gfe_upstream_retries_total{pool="pool"} 1"#)
        .await;
    proxy
        .wait_for_metric(&format!(
            r#"gfe_upstream_errors_total{{pool="pool",backend="{dead}",kind="connect_refused"}} 1"#
        ))
        .await;
}

#[tokio::test]
async fn does_not_retry_a_post() {
    let (logs, _guard) = CapturedLogs::start();
    let (proxy, _) = proxy_with_a_dead_first_backend(spawn_upload_upstream().await).await;

    let response = raw_exchange(
        proxy.addr,
        "POST /x HTTP/1.1\r\nhost: a.example.org\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
    )
    .await;
    let event = logs.access_event().await;

    assert!(response.starts_with("HTTP/1.1 502"), "{response}");
    assert_eq!(event["attempts"], 1);
    assert_eq!(event["error"], "upstream_connect_refused");
    assert!(!proxy.metrics().contains("gfe_upstream_retries_total{"));
}

/// A request with a body cannot be replayed once it has been streamed, so it
/// is attempted once whatever its method.
#[tokio::test]
async fn does_not_retry_a_get_with_a_body() {
    let (logs, _guard) = CapturedLogs::start();
    let (proxy, _) = proxy_with_a_dead_first_backend(spawn_upload_upstream().await).await;

    let response = raw_exchange(
        proxy.addr,
        "GET /x HTTP/1.1\r\nhost: a.example.org\r\ntransfer-encoding: chunked\r\n\
         connection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    )
    .await;
    let event = logs.access_event().await;

    assert!(response.starts_with("HTTP/1.1 502"), "{response}");
    assert_eq!(event["attempts"], 1);
}

#[tokio::test]
async fn retries_once_only() {
    let (logs, _guard) = CapturedLogs::start();
    let dead = closed_port();
    let proxy = Proxy::start(&forwarding_config(dead)).await;

    let (status, _) = http_get(proxy.addr, "a.example.org", "/").await;
    let event = logs.access_event().await;

    assert_eq!(status, 502);
    assert_eq!(event["error"], "upstream_connect_refused");
    // A bodyless GET is retried once, here against the only backend there is.
    assert_eq!(event["attempts"], 2);
    for expected in [
        format!(
            r#"gfe_upstream_errors_total{{pool="pool",backend="{dead}",kind="connect_refused"}} 2"#
        ),
        r#"gfe_upstream_retries_total{pool="pool"} 1"#.to_string(),
        format!(r#"gfe_upstream_requests_in_flight{{pool="pool",backend="{dead}"}} 0"#),
        "gfe_upstream_connect_errors_total 2".to_string(),
    ] {
        proxy.wait_for_metric(&expected).await;
    }
}

/// A backend that sends response headers and part of the body, then closes.
async fn spawn_upstream_dying_mid_body() -> SocketAddr {
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
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\npartial")
                    .await;
                let _ = stream.flush().await;
                // Dropped: the connection closes 93 bytes short.
            });
        }
    });
    addr
}

#[tokio::test]
async fn does_not_retry_once_the_response_has_started() {
    let (logs, _guard) = CapturedLogs::start();
    let proxy = Proxy::start(&forwarding_config(spawn_upstream_dying_mid_body().await)).await;

    let response = raw_exchange(
        proxy.addr,
        "GET / HTTP/1.1\r\nhost: a.example.org\r\nconnection: close\r\n\r\n",
    )
    .await;
    let event = logs.access_event().await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("partial"), "{response}");
    assert_eq!(event["attempts"], 1);
    assert_eq!(event["status"], 200);
    assert_eq!(event["termination"], "upstream_abort");
    assert!(!proxy.metrics().contains("gfe_upstream_retries_total{"));
}
