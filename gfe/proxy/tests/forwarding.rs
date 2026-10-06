//! What a forwarded request and its response look like on the other side:
//! headers, host, bodies streamed in both directions, protocol translation,
//! connection reuse, and what is refused instead of forwarded.

mod common;

use bytes::Bytes;
use common::*;
use gfe_config::Scheme;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response};
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A backend answering with the request's headers, one `name: value` line
/// each, and its version.
async fn spawn_header_echo() -> std::net::SocketAddr {
    serve_http1(|req: Request<Incoming>| async move {
        let mut lines = format!("version={:?}\n", req.version());
        for (name, value) in req.headers() {
            lines.push_str(&format!("{name}: {}\n", value.to_str().unwrap_or("?")));
        }
        Response::new(Full::new(Bytes::from(lines)))
    })
    .await
}

fn header_line<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    body.lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
}

#[tokio::test]
async fn adds_the_forwarding_headers() {
    let proxy = Proxy::start(&forwarding_config(spawn_header_echo().await)).await;

    let answer = get_with(
        proxy.addr,
        "a.example.org",
        "/",
        &[("x-forwarded-for", "198.51.100.1"), ("x-request-id", "abc")],
    )
    .await;

    let body = &answer.body;
    assert_eq!(
        header_line(body, "x-forwarded-for"),
        Some("198.51.100.1, 127.0.0.1")
    );
    assert_eq!(header_line(body, "x-forwarded-proto"), Some("http"));
    assert_eq!(header_line(body, "x-forwarded-host"), Some("a.example.org"));
    assert_eq!(
        header_line(body, "forwarded"),
        Some("for=127.0.0.1;host=a.example.org;proto=http")
    );
    assert_eq!(header_line(body, "x-request-id"), Some("abc"));
    assert_eq!(answer.headers["x-request-id"], "abc");
}

#[tokio::test]
async fn says_https_for_a_request_that_arrived_over_tls_and_adds_hsts() {
    let mut node = node_config();
    node.tls.hsts = "max-age=31536000".into();
    let upstream = spawn_header_echo().await;
    let proxy = Proxy::start_with(
        &forwarding_config(upstream),
        node,
        Some(tls_info("a.example.org")),
    )
    .await;

    let answer = get_with(proxy.addr, "a.example.org", "/", &[]).await;

    assert_eq!(
        header_line(&answer.body, "x-forwarded-proto"),
        Some("https")
    );
    assert_eq!(
        answer.headers["strict-transport-security"],
        "max-age=31536000"
    );
}

#[tokio::test]
async fn adds_no_hsts_to_cleartext_responses() {
    let mut node = node_config();
    node.tls.hsts = "max-age=31536000".into();
    let proxy = Proxy::start_with(&forwarding_config(spawn_upstream().await), node, None).await;

    let answer = get_with(proxy.addr, "a.example.org", "/", &[]).await;

    assert!(!answer.headers.contains_key("strict-transport-security"));
}

#[tokio::test]
async fn backend_sees_the_host_an_http1_client_asked_for() {
    let proxy = Proxy::start(&forwarding_config(spawn_upstream().await)).await;

    let (_, body) = http_get(proxy.addr, "a.example.org", "/").await;

    assert!(body.ends_with("host=a.example.org"), "{body}");
}

#[tokio::test]
async fn backend_sees_the_host_an_http2_client_asked_for() {
    let proxy = Proxy::start(&forwarding_config(spawn_upstream().await)).await;

    let answer = h2_request(proxy.addr, "GET", "http://a.example.org/", "").await;

    assert_eq!(answer.status, 200, "{}", answer.body);
    assert!(
        answer.body.ends_with("host=a.example.org"),
        "{}",
        answer.body
    );
}

#[tokio::test]
async fn keeps_the_port_of_the_host_the_client_asked_for() {
    let proxy = Proxy::start(&forwarding_config(spawn_upstream().await)).await;

    let answer = h2_request(proxy.addr, "GET", "http://a.example.org:8080/", "").await;

    assert!(
        answer.body.ends_with("host=a.example.org:8080"),
        "{}",
        answer.body
    );
}

#[tokio::test]
async fn sends_no_host_to_an_h2c_pool() {
    let upstream = spawn_h2c_describing_upstream().await;
    let mut cfg = forwarding_config(upstream);
    cfg.pools[0].scheme = Scheme::H2c;
    let proxy = Proxy::start(&cfg).await;

    let (_, body) = http_get(proxy.addr, "a.example.org", "/").await;

    assert_eq!(
        body,
        format!("version=HTTP/2.0 host=none authority={upstream}")
    );
}

#[tokio::test]
async fn strips_hop_by_hop_headers_and_those_connection_names() {
    let proxy = Proxy::start(&forwarding_config(spawn_header_echo().await)).await;

    let answer = get_with(
        proxy.addr,
        "a.example.org",
        "/",
        &[
            ("connection", "keep-alive, x-internal"),
            ("keep-alive", "timeout=5"),
            ("x-internal", "secret"),
            ("proxy-authorization", "Basic x"),
            ("te", "gzip"),
            ("accept", "*/*"),
        ],
    )
    .await;

    let body = &answer.body;
    for stripped in ["keep-alive", "x-internal", "proxy-authorization", "te"] {
        assert_eq!(header_line(body, stripped), None, "{stripped} in {body}");
    }
    assert_eq!(header_line(body, "accept"), Some("*/*"));
}

#[tokio::test]
async fn keeps_te_trailers() {
    let proxy = Proxy::start(&forwarding_config(spawn_header_echo().await)).await;

    let answer = get_with(proxy.addr, "a.example.org", "/", &[("te", "trailers")]).await;

    assert_eq!(header_line(&answer.body, "te"), Some("trailers"));
}

#[tokio::test]
async fn strips_hop_by_hop_headers_of_the_response() {
    let upstream = serve_http1(|_req: Request<Incoming>| async {
        Response::builder()
            .header("connection", "x-internal")
            .header("x-internal", "secret")
            .header("keep-alive", "timeout=5")
            .header("x-kept", "yes")
            .body(Full::new(Bytes::from("ok")))
            .unwrap()
    })
    .await;
    let proxy = Proxy::start(&forwarding_config(upstream)).await;

    let answer = get_with(proxy.addr, "a.example.org", "/", &[]).await;

    assert!(!answer.headers.contains_key("x-internal"));
    assert!(!answer.headers.contains_key("keep-alive"));
    assert_eq!(answer.headers["x-kept"], "yes");
}

const SIXTEEN_MIB: usize = 16 * 1024 * 1024;

#[tokio::test]
async fn streams_a_large_upload_intact() {
    let proxy = Proxy::start(&forwarding_config(spawn_upload_upstream().await)).await;
    let mut sender = h1_sender(proxy.addr).await;
    // Sent in 64 KiB chunks without a content-length: streamed, not held.
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        let chunk = Bytes::from(vec![b'x'; 64 * 1024]);
        for _ in 0..SIXTEEN_MIB / chunk.len() {
            tx.send(Frame::data(chunk.clone())).await.unwrap();
        }
    });
    let body = ChannelBody(rx);
    let req = Request::builder()
        .method("POST")
        .uri("/upload")
        .header("host", "a.example.org")
        .body(body)
        .unwrap();

    let answer = collect(sender.send_request(req).await.unwrap()).await;

    assert_eq!(answer.status, 200);
    assert_eq!(answer.body, format!("received {SIXTEEN_MIB}"));
}

#[tokio::test]
async fn streams_a_large_download_intact() {
    let upstream = serve_http1(|_req: Request<Incoming>| async {
        Response::new(Full::new(Bytes::from(vec![b'y'; SIXTEEN_MIB])))
    })
    .await;
    let proxy = Proxy::start(&forwarding_config(upstream)).await;
    let mut sender = h1_sender(proxy.addr).await;
    let req = Request::builder()
        .uri("/download")
        .header("host", "a.example.org")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();

    assert_eq!(body.len(), SIXTEEN_MIB);
    assert!(body.iter().all(|b| *b == b'y'));
}

#[tokio::test]
async fn answers_head_without_a_body() {
    let upstream = serve_http1(|req: Request<Incoming>| async move {
        assert_eq!(req.method(), "HEAD");
        Response::builder()
            .header("content-length", "5")
            .body(Empty::<Bytes>::new())
            .unwrap()
    })
    .await;
    let proxy = Proxy::start(&forwarding_config(upstream)).await;

    let response = raw_exchange(
        proxy.addr,
        "HEAD / HTTP/1.1\r\nhost: a.example.org\r\nconnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response.to_ascii_lowercase().contains("content-length: 5"),
        "{response}"
    );
    assert!(response.ends_with("\r\n\r\n"), "{response}");
}

#[tokio::test]
async fn forwards_the_body_of_a_chunked_delete() {
    let proxy = Proxy::start(&forwarding_config(spawn_upload_upstream().await)).await;

    let response = raw_exchange(
        proxy.addr,
        "DELETE /resource HTTP/1.1\r\nhost: a.example.org\r\ntransfer-encoding: chunked\r\n\
         connection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("received 5"), "{response}");
}

#[tokio::test]
async fn relays_a_chunked_response() {
    let upstream = serve_http1(|_req: Request<Incoming>| async {
        // No length: hyper sends it chunked.
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        tokio::spawn(async move {
            for part in ["one,", "two"] {
                let _ = tx.send(hyper::body::Frame::data(Bytes::from(part))).await;
            }
        });
        Response::new(ChannelBody(rx))
    })
    .await;
    let proxy = Proxy::start(&forwarding_config(upstream)).await;

    let (status, body) = http_get(proxy.addr, "a.example.org", "/").await;

    assert_eq!(status, 200);
    assert_eq!(body, "one,two");
}

#[tokio::test]
async fn forwards_the_body_of_an_http2_request_without_content_length() {
    let proxy = Proxy::start(&forwarding_config(spawn_upload_upstream().await)).await;

    let answer = h2_request(
        proxy.addr,
        "DELETE",
        "http://a.example.org/resource",
        "hello",
    )
    .await;

    assert_eq!(answer.status, 200, "{}", answer.body);
    assert_eq!(answer.body, "received 5");
}

#[tokio::test]
async fn http2_client_reaches_an_http1_backend() {
    let proxy = Proxy::start(&forwarding_config(spawn_header_echo().await)).await;

    let answer = h2_request(proxy.addr, "GET", "http://a.example.org/", "").await;

    assert_eq!(answer.status, 200);
    assert!(
        answer.body.starts_with("version=HTTP/1.1"),
        "{}",
        answer.body
    );
}

#[tokio::test]
async fn http1_client_reaches_an_http1_backend() {
    let proxy = Proxy::start(&forwarding_config(spawn_header_echo().await)).await;

    let answer = get_with(proxy.addr, "a.example.org", "/", &[]).await;

    assert!(
        answer.body.starts_with("version=HTTP/1.1"),
        "{}",
        answer.body
    );
}

#[tokio::test]
async fn relays_a_request_that_expects_100_continue() {
    let proxy = Proxy::start(&forwarding_config(spawn_upload_upstream().await)).await;
    let mut stream = TcpStream::connect(proxy.addr).await.unwrap();
    stream
        .write_all(
            b"POST /upload HTTP/1.1\r\nhost: a.example.org\r\ncontent-length: 5\r\n\
              expect: 100-continue\r\nconnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    // A client waits for `100 Continue` a moment, then sends the body anyway.
    let mut interim = [0u8; 12];
    let continued =
        tokio::time::timeout(Duration::from_millis(500), stream.read_exact(&mut interim)).await;
    if let Ok(read) = continued {
        read.unwrap();
        assert_eq!(
            &interim,
            b"HTTP/1.1 100",
            "{:?}",
            String::from_utf8_lossy(&interim)
        );
    }
    stream.write_all(b"hello").await.unwrap();
    let rest = read_until_closed(&mut stream).await;

    assert!(rest.contains("HTTP/1.1 200"), "{rest}");
    assert!(rest.ends_with("received 5"), "{rest}");
}

#[tokio::test]
async fn reuses_an_upstream_connection_for_sequential_requests() {
    let (upstream, requests, connections) = spawn_counting_upstream().await;
    let proxy = Proxy::start(&forwarding_config(upstream)).await;

    for _ in 0..3 {
        let (status, _) = http_get(proxy.addr, "a.example.org", "/").await;
        assert_eq!(status, 200);
    }

    assert_eq!(requests.load(Ordering::SeqCst), 3);
    assert_eq!(connections.load(Ordering::SeqCst), 1);
}

/// GFE does not relay protocol upgrades. Forwarding the handshake without
/// its hop-by-hop `Connection: Upgrade` would turn it into a plain request,
/// so it is refused instead, before a backend is chosen.
#[tokio::test]
async fn refuses_a_websocket_handshake_with_501() {
    let (logs, _guard) = CapturedLogs::start();
    let (upstream, requests, _) = spawn_counting_upstream().await;
    let proxy = Proxy::start(&forwarding_config(upstream)).await;

    let answer = get_with(
        proxy.addr,
        "a.example.org",
        "/chat",
        &[
            ("connection", "keep-alive, Upgrade"),
            ("upgrade", "websocket"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("sec-websocket-version", "13"),
        ],
    )
    .await;
    let event = logs.access_event().await;

    assert_eq!(answer.status, 501);
    assert_eq!(event["error"], "upgrade_not_supported");
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    proxy
        .wait_for_metric(
            r#"gfe_requests_total{listener="http",vhost="a.example.org",route="web",status="501"} 1"#,
        )
        .await;
}

#[tokio::test]
async fn serves_a_request_that_offers_to_switch_to_http2() {
    let (upstream, requests, _) = spawn_counting_upstream().await;
    let proxy = Proxy::start(&forwarding_config(upstream)).await;

    // What `curl --http2` sends to a cleartext URL: an offer, which a server
    // that does not take it up answers over HTTP/1.1.
    let answer = get_with(
        proxy.addr,
        "a.example.org",
        "/",
        &[
            ("connection", "Upgrade, HTTP2-Settings"),
            ("upgrade", "h2c"),
            ("http2-settings", "AAMAAABkAAQCAAAAAAIAAAAA"),
        ],
    )
    .await;

    assert_eq!(answer.status, 200);
    assert_eq!(requests.load(Ordering::SeqCst), 1);
}

/// A request whose target is not a path (asterisk form `OPTIONS *`, or
/// authority form `CONNECT`) names nothing a backend could serve: it is
/// refused before a backend is chosen, so no backend is blamed for it.
#[tokio::test]
async fn refuses_a_request_whose_target_is_not_a_path() {
    let upstream = spawn_upstream().await;
    for request in [
        "OPTIONS * HTTP/1.1\r\nhost: a.example.org\r\nconnection: close\r\n\r\n",
        "CONNECT a.example.org:443 HTTP/1.1\r\nhost: a.example.org\r\nconnection: close\r\n\r\n",
    ] {
        let (logs, _guard) = CapturedLogs::start();
        let proxy = Proxy::start(&forwarding_config(upstream)).await;

        let response = raw_exchange(proxy.addr, request).await;
        let event = logs.access_event().await;

        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        assert_eq!(event["error"], "unsupported_request_target");
        assert!(event["backend"].is_null(), "{event}");
        let metrics = proxy.metrics();
        assert!(!metrics.contains("gfe_upstream_errors_total{"), "{metrics}");
        assert!(
            !metrics.contains("gfe_upstream_requests_total{"),
            "{metrics}"
        );
    }
}
