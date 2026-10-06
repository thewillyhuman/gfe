use super::*;
use crate::edge::RequestHandler;
use crate::handler::respond;
use crate::handler::test_support::*;
use gfe_config::{LbPolicy, NodeConfig};
use netkit_health_checking::HealthStatus;
use netkit_http::body::{BodyExt, Frame};
use netkit_http::{Bytes, HeaderMap, Method, StatusCode};
use netkit_tls::TlsInfo;
use std::net::SocketAddr;
use std::time::Duration;

/// Forwards every request for `a.example.org` to its pool, and answers a
/// failed forward itself, as the handler does for a route that forwards.
struct Forwarder {
    state: Arc<State>,
    pool: Arc<Pool<Scheme>>,
}

impl RequestHandler for Forwarder {
    async fn handle(&self, conn: Arc<ConnInfo>, request: Request<Incoming>) -> Response<BoxBody> {
        let id = request::request_id(request.headers());
        let mut record = RequestRecord::begin(
            Arc::clone(self.state.metrics()),
            Arc::clone(&conn),
            &request,
            "a.example.org".into(),
            id,
        );
        match forward(&self.state, &conn, &self.pool, request, &mut record).await {
            Ok(response) => record.respond(response),
            Err(Unanswered::Refused(refusal)) => {
                record.failed(refusal.reason());
                let answer = respond::refusal(refusal, record.request_id(), record.is_grpc());
                record.respond(answer)
            }
            Err(Unanswered::ClientGone) => Response::new(body::empty()),
        }
    }
}

/// A node configured by `config` forwarding to `pool`, its connections
/// told they negotiated `tls`.
async fn forwarding_with(
    config: &NodeConfig,
    pool: Arc<Pool<Scheme>>,
    tls: Option<TlsInfo>,
) -> (SocketAddr, Arc<State>) {
    let state = state_with(config);
    let forwarder = Forwarder {
        state: Arc::clone(&state),
        pool,
    };
    (serve(Arc::new(forwarder), tls).await, state)
}

/// A node with a default config forwarding to `pool` over cleartext.
async fn forwarding(pool: Arc<Pool<Scheme>>) -> (SocketAddr, Arc<State>) {
    forwarding_with(&node_config(), pool, None).await
}

fn config_with_timeouts(first_byte: Duration, total: Duration) -> NodeConfig {
    let mut config = node_config();
    config.timeouts.upstream_first_byte = first_byte;
    config.timeouts.request_total = total;
    config
}

/// The line of the upstream metric `metric` of `backend` with `label`,
/// counted `n` times.
fn upstream(metric: &str, backend: SocketAddr, label: &str, n: u32) -> String {
    format!(r#"gfe_upstream_{metric}{{pool="pool",backend="{backend}",{label}}} {n}"#)
}

fn requests_total(status: u16) -> String {
    format!(
        r#"gfe_requests_total{{listener="http",vhost="none",route="none",status="{status}"}} 1"#
    )
}

// ---------------------------------------------------------------------------
// The request and the response
// ---------------------------------------------------------------------------

#[tokio::test]
async fn backend_gets_the_forwarding_headers_and_the_host_asked_for() {
    let (proxy, _) = forwarding(pool(Scheme::Http, &[describing_backend().await])).await;

    let response = send(proxy, get("a.example.org:8080", "/x?q=1")).await;
    let seen = text(response).await;

    assert!(seen.starts_with("GET /x?q=1 HTTP/1.1\n"), "{seen}");
    assert_eq!(header_line(&seen, "host"), Some("a.example.org:8080"));
    assert_eq!(header_line(&seen, "x-forwarded-for"), Some("127.0.0.1"));
    assert_eq!(header_line(&seen, "x-forwarded-proto"), Some("http"));
    assert_eq!(
        header_line(&seen, "x-forwarded-host"),
        Some("a.example.org")
    );
    let id = header_line(&seen, "x-request-id").unwrap();
    assert_eq!(id.len(), 32, "{seen}");
}

#[tokio::test]
async fn backend_gets_the_host_an_http2_client_asked_for() {
    let (proxy, _) = forwarding(pool(Scheme::Http, &[describing_backend().await])).await;
    let request = Request::builder()
        .uri("http://a.example.org/x")
        .version(Version::HTTP_2)
        .body(body::empty())
        .unwrap();

    let seen = text(send_h2(proxy, request).await).await;

    assert!(seen.contains("HTTP/1.1"), "{seen}");
    assert_eq!(header_line(&seen, "host"), Some("a.example.org"));
}

#[tokio::test]
async fn an_h2c_backend_is_named_by_its_own_address_and_gets_no_host() {
    let backend = describing_backend().await;
    let (proxy, _) = forwarding(pool(Scheme::H2c, &[backend])).await;

    let seen = text(send(proxy, get("a.example.org", "/x")).await).await;

    assert!(
        seen.starts_with(&format!("GET http://{backend}/x HTTP/2.0\n")),
        "{seen}"
    );
    assert_eq!(header_line(&seen, "host"), None);
    assert_eq!(
        header_line(&seen, "x-forwarded-host"),
        Some("a.example.org")
    );
}

#[tokio::test]
async fn backend_gets_the_clients_request_id_and_the_client_gets_it_back() {
    let (proxy, _) = forwarding(pool(Scheme::Http, &[describing_backend().await])).await;
    let mut request = get("a.example.org", "/");
    request
        .headers_mut()
        .insert("x-request-id", HeaderValue::from_static("from-client"));

    let response = send(proxy, request).await;

    assert_eq!(response.headers()["x-request-id"], "from-client");
    let seen = text(response).await;
    assert_eq!(header_line(&seen, "x-request-id"), Some("from-client"));
}

#[tokio::test]
async fn keeps_the_request_id_of_the_backends_response() {
    let backend = backend(|_request| async {
        let mut response = Response::new(body::empty());
        response
            .headers_mut()
            .insert("x-request-id", HeaderValue::from_static("from-backend"));
        response
    })
    .await;
    let (proxy, _) = forwarding(pool(Scheme::Http, &[backend])).await;

    let response = send(proxy, get("a.example.org", "/")).await;

    assert_eq!(response.headers()["x-request-id"], "from-backend");
}

#[tokio::test]
async fn strips_the_hop_by_hop_headers_of_the_response() {
    let backend = backend(|_request| async {
        let mut response = Response::new(body::full("ok"));
        let headers = response.headers_mut();
        headers.insert("connection", HeaderValue::from_static("x-internal"));
        headers.insert("x-internal", HeaderValue::from_static("1"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("x-kept", HeaderValue::from_static("1"));
        response
    })
    .await;
    let (proxy, _) = forwarding(pool(Scheme::Http, &[backend])).await;

    let response = send(proxy, get("a.example.org", "/")).await;

    assert!(!response.headers().contains_key("x-internal"));
    assert!(!response.headers().contains_key("keep-alive"));
    assert!(response.headers().contains_key("x-kept"));
    assert_eq!(text(response).await, "ok");
}

#[tokio::test]
async fn says_https_for_a_request_over_tls_and_adds_hsts() {
    let mut config = node_config();
    config.tls.hsts = "max-age=31536000".into();
    let backends = pool(Scheme::Http, &[describing_backend().await]);
    let (proxy, _) = forwarding_with(&config, backends, Some(tls_info("a.example.org"))).await;

    let response = send(proxy, get("a.example.org", "/")).await;

    assert_eq!(
        response.headers()["strict-transport-security"],
        "max-age=31536000"
    );
    let seen = text(response).await;
    assert_eq!(header_line(&seen, "x-forwarded-proto"), Some("https"));
}

#[tokio::test]
async fn adds_no_hsts_to_cleartext_responses() {
    let mut config = node_config();
    config.tls.hsts = "max-age=31536000".into();
    let backends = pool(Scheme::Http, &[describing_backend().await]);
    let (proxy, _) = forwarding_with(&config, backends, None).await;

    let response = send(proxy, get("a.example.org", "/")).await;

    assert!(!response.headers().contains_key("strict-transport-security"));
}

#[tokio::test]
async fn refuses_a_websocket_handshake_with_501() {
    let (proxy, state) = forwarding(pool(Scheme::Http, &[describing_backend().await])).await;
    let mut request = get("a.example.org", "/");
    request
        .headers_mut()
        .insert("connection", HeaderValue::from_static("Upgrade"));
    request
        .headers_mut()
        .insert("upgrade", HeaderValue::from_static("websocket"));

    let response = send(proxy, request).await;

    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    wait_for_metric(&state, &requests_total(501)).await;
}

#[tokio::test]
async fn serves_a_request_that_offers_to_switch_to_http2() {
    let (proxy, _) = forwarding(pool(Scheme::Http, &[describing_backend().await])).await;
    let mut request = get("a.example.org", "/");
    let headers = request.headers_mut();
    headers.insert(
        "connection",
        HeaderValue::from_static("Upgrade, HTTP2-Settings"),
    );
    headers.insert("upgrade", HeaderValue::from_static("h2c"));
    headers.insert(
        "http2-settings",
        HeaderValue::from_static("AAMAAABkAAQAoAAAAAIAAAAA"),
    );

    let response = send(proxy, request).await;

    assert_eq!(response.status(), StatusCode::OK);
    let seen = text(response).await;
    assert_eq!(header_line(&seen, "upgrade"), None);
    assert_eq!(header_line(&seen, "http2-settings"), None);
}

#[tokio::test]
async fn refuses_a_target_that_is_not_a_path_with_400() {
    let (proxy, _) = forwarding(pool(Scheme::Http, &[describing_backend().await])).await;
    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri("*")
        .header("host", "a.example.org")
        .body(body::empty())
        .unwrap();

    let response = send(proxy, request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        text(response)
            .await
            .starts_with("400 unsupported request target")
    );
}

#[tokio::test]
async fn streams_an_upload_and_counts_its_bytes() {
    let backend = backend(|request: Request<Incoming>| async move {
        let received = request.into_body().collect().await.unwrap().to_bytes();
        Response::new(body::full(received.len().to_string()))
    })
    .await;
    let (proxy, state) = forwarding(pool(Scheme::Http, &[backend])).await;
    let upload = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header("host", "a.example.org")
        .body(body::full(vec![b'x'; 100_000]))
        .unwrap();

    let response = send(proxy, upload).await;

    assert_eq!(text(response).await, "100000");
    wait_for_metric(
        &state,
        r#"gfe_request_body_bytes_total{listener="http",vhost="none",route="none"} 100000"#,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Failures, and what is retried
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unreachable_backend_is_a_502_counted_against_it() {
    let closed = closed_port();
    let (proxy, state) = forwarding(pool(Scheme::Http, &[closed])).await;
    let (logs, _capturing) = Logs::capture();

    let response = send(proxy, get("a.example.org", "/")).await;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(text(response).await.starts_with("502 upstream error"));
    let event = logs.access_event().await;
    assert_eq!(event["error"], "upstream_connect_refused");
    assert_eq!(event["backend"], closed.to_string());
    assert_eq!(event["attempts"], 2);
    assert!(exposes(
        &state,
        &upstream("errors_total", closed, r#"kind="connect_refused""#, 2)
    ));
    assert!(exposes(&state, "gfe_upstream_connect_errors_total 2"));
    assert!(exposes(
        &state,
        &upstream("requests_total", closed, r#"status="502""#, 2)
    ));
}

#[tokio::test]
async fn retries_a_bodyless_get_once_against_another_backend() {
    let closed = closed_port();
    let up = describing_backend().await;
    let (proxy, state) = forwarding(pool(Scheme::Http, &[closed, up])).await;

    // Round robin: at least one of the two requests is tried on the closed
    // port first, and retried on the other backend.
    let first = send(proxy, get("a.example.org", "/")).await.status();
    let second = send(proxy, get("a.example.org", "/")).await.status();

    assert_eq!((first, second), (StatusCode::OK, StatusCode::OK));
    let retried = |n: u32| {
        exposes(
            &state,
            &format!(r#"gfe_upstream_retries_total{{pool="pool"}} {n}"#),
        )
    };
    assert!(retried(1) || retried(2));
}

#[tokio::test]
async fn retries_once_only() {
    let closed = closed_port();
    let (proxy, state) = forwarding(pool(Scheme::Http, &[closed])).await;

    let response = send(proxy, get("a.example.org", "/")).await;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(exposes(
        &state,
        r#"gfe_upstream_retries_total{pool="pool"} 1"#
    ));
}

#[tokio::test]
async fn does_not_retry_a_post() {
    let closed = closed_port();
    let up = describing_backend().await;
    let (proxy, state) = forwarding(pool(Scheme::Http, &[closed, up])).await;
    let post = || {
        Request::builder()
            .method(Method::POST)
            .uri("/")
            .header("host", "a.example.org")
            .body(body::empty())
            .unwrap()
    };

    let first = send(proxy, post()).await.status();
    let second = send(proxy, post()).await.status();

    let mut statuses = [first, second];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::BAD_GATEWAY]);
    assert!(!exposes(&state, "gfe_upstream_retries_total{"));
}

#[tokio::test]
async fn does_not_retry_a_get_with_a_body() {
    let closed = closed_port();
    let (proxy, state) = forwarding(pool(Scheme::Http, &[closed])).await;
    let request = Request::builder()
        .uri("/")
        .header("host", "a.example.org")
        .body(body::full("payload"))
        .unwrap();

    let response = send(proxy, request).await;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(!exposes(&state, "gfe_upstream_retries_total{"));
}

#[tokio::test]
async fn a_backend_that_resets_before_answering_is_upstream_reset() {
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = socket.local_addr().unwrap();
    tokio::spawn(async move {
        // Read the request, then hang up without a word.
        while let Ok((mut stream, _)) = socket.accept().await {
            let mut buffer = [0; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await;
        }
    });
    let (proxy, _) = forwarding(pool(Scheme::Http, &[backend])).await;
    let (logs, _capturing) = Logs::capture();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header("host", "a.example.org")
        .body(body::empty())
        .unwrap();

    let response = send(proxy, request).await;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(logs.access_event().await["error"], "upstream_reset");
}

#[tokio::test]
async fn a_backend_that_breaks_off_its_response_is_an_upstream_abort() {
    let backend = backend(|_request| async {
        let (sender, content) = channel_body();
        tokio::spawn(async move {
            sender
                .send(Frame::data(Bytes::from_static(b"part")))
                .await
                .unwrap();
            // The head and the first part reach the client before the cut.
            tokio::time::sleep(Duration::from_millis(50)).await;
            // Dropping a body that announced a length it did not send cuts
            // the response short.
        });
        let mut response = Response::new(content);
        response
            .headers_mut()
            .insert("content-length", HeaderValue::from_static("100"));
        response
    })
    .await;
    let (proxy, state) = forwarding(pool(Scheme::Http, &[backend])).await;
    let (logs, _capturing) = Logs::capture();

    let response = send(proxy, get("a.example.org", "/")).await;
    let _ = response.into_body().collect().await;

    let event = logs.access_event().await;
    assert_eq!(event["termination"], "upstream_abort");
    assert_eq!(event["status"], 200);
    assert!(exposes(
        &state,
        r#"gfe_requests_aborted_total{listener="http",vhost="none",route="none",by="upstream"} 1"#
    ));
}

#[tokio::test]
async fn keeps_the_backend_busy_until_the_response_ends() {
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    let released = Arc::new(tokio::sync::Mutex::new(Some(released)));
    let backend = backend(move |_request| {
        let released = Arc::clone(&released);
        async move {
            let (sender, content) = channel_body();
            let released = released.lock().await.take().unwrap();
            tokio::spawn(async move {
                sender
                    .send(Frame::data(Bytes::from_static(b"start")))
                    .await
                    .unwrap();
                let _ = released.await;
            });
            Response::new(content)
        }
    })
    .await;
    let (proxy, state) = forwarding(pool(Scheme::Http, &[backend])).await;
    let in_flight = |n: u8| {
        format!(r#"gfe_upstream_requests_in_flight{{pool="pool",backend="{backend}"}} {n}"#)
    };

    let mut response = send(proxy, get("a.example.org", "/")).await;
    response.body_mut().frame().await.unwrap().unwrap();
    assert!(exposes(&state, &in_flight(1)));
    release.send(()).unwrap();
    let _ = response.into_body().collect().await;

    wait_for_metric(&state, &in_flight(0)).await;
}

// ---------------------------------------------------------------------------
// Timeouts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gives_up_on_a_backend_silent_for_upstream_first_byte() {
    let backend = backend_answering_after(Duration::from_secs(5)).await;
    let config = config_with_timeouts(Duration::from_millis(50), Duration::from_secs(60));
    let (proxy, state) = forwarding_with(&config, pool(Scheme::Http, &[backend]), None).await;

    let response = send(proxy, get("a.example.org", "/")).await;

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(exposes(
        &state,
        &upstream("errors_total", backend, r#"kind="timeout""#, 1)
    ));
    assert!(exposes(
        &state,
        &upstream("requests_total", backend, r#"status="504""#, 1)
    ));
    // A timeout is not retried.
    assert!(!exposes(&state, "gfe_upstream_retries_total{"));
}

#[tokio::test]
async fn request_total_bounds_the_wait_for_a_response() {
    // As in v1.1.0: once the request is sent, the response is due within
    // request_total of when forwarding began, whatever upstream_first_byte.
    let backend = backend_answering_after(Duration::from_secs(5)).await;
    let config = config_with_timeouts(Duration::from_secs(30), Duration::from_millis(50));
    let (proxy, _) = forwarding_with(&config, pool(Scheme::Http, &[backend]), None).await;

    let response = send(proxy, get("a.example.org", "/")).await;

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
}

#[tokio::test]
async fn a_response_that_has_started_is_not_cut_by_upstream_first_byte() {
    let backend = backend(|_request| async {
        let (sender, content) = channel_body();
        tokio::spawn(async move {
            sender
                .send(Frame::data(Bytes::from_static(b"a")))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            sender
                .send(Frame::data(Bytes::from_static(b"b")))
                .await
                .unwrap();
        });
        Response::new(content)
    })
    .await;
    let config = config_with_timeouts(Duration::from_millis(50), Duration::from_millis(50));
    let (proxy, _) = forwarding_with(&config, pool(Scheme::Http, &[backend]), None).await;

    let response = send(proxy, get("a.example.org", "/")).await;

    assert_eq!(text(response).await, "ab");
}

/// An upload of `chunks` pieces sent `every` apart, and the backend's
/// count of what it received.
async fn upload_slowly(scheme: Scheme, chunks: usize, every: Duration) -> (StatusCode, String) {
    let backend = backend(|request: Request<Incoming>| async move {
        let received = request.into_body().collect().await.unwrap().to_bytes();
        Response::new(body::full(received.len().to_string()))
    })
    .await;
    let config = config_with_timeouts(Duration::from_millis(100), Duration::from_secs(60));
    let (proxy, _) = forwarding_with(&config, pool(scheme, &[backend]), None).await;
    let (sender, content) = channel_body();
    tokio::spawn(async move {
        for _ in 0..chunks {
            tokio::time::sleep(every).await;
            sender
                .send(Frame::data(Bytes::from_static(b"x")))
                .await
                .unwrap();
        }
    });
    let upload = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header("host", "a.example.org")
        .body(content)
        .unwrap();

    let response = send(proxy, upload).await;
    let status = response.status();
    (status, text(response).await)
}

#[tokio::test]
async fn an_upload_slower_than_upstream_first_byte_succeeds_while_it_progresses() {
    let (status, received) = upload_slowly(Scheme::Http, 6, Duration::from_millis(40)).await;

    assert_eq!((status, received.as_str()), (StatusCode::OK, "6"));
}

#[tokio::test]
async fn an_upload_to_an_h2c_pool_is_bounded_by_its_progress() {
    // Pingora armed the wait for the response head once on HTTP/2 upstream
    // connections, and answered this upload 408.
    let (status, received) = upload_slowly(Scheme::H2c, 6, Duration::from_millis(40)).await;

    assert_eq!((status, received.as_str()), (StatusCode::OK, "6"));
}

#[tokio::test]
async fn a_stalled_upload_is_answered_408_without_blaming_the_backend() {
    let backend = backend(|request: Request<Incoming>| async move {
        let _ = request.into_body().collect().await;
        Response::new(body::empty())
    })
    .await;
    let config = config_with_timeouts(Duration::from_millis(50), Duration::from_secs(60));
    let (proxy, state) = forwarding_with(&config, pool(Scheme::Http, &[backend]), None).await;
    let (sender, content) = channel_body();
    sender
        .send(Frame::data(Bytes::from_static(b"start")))
        .await
        .unwrap();
    let upload = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header("host", "a.example.org")
        .body(content)
        .unwrap();

    let response = send(proxy, upload).await;
    drop(sender);

    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert!(!exposes(&state, "gfe_upstream_errors_total{"));
}

#[tokio::test]
async fn a_backend_that_stops_reading_an_upload_is_answered_504() {
    // Takes the request head and never reads the body nor answers.
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = socket.accept().await {
            held.push(stream);
        }
    });
    let config = config_with_timeouts(Duration::from_millis(100), Duration::from_secs(60));
    let (proxy, state) = forwarding_with(&config, pool(Scheme::Http, &[backend]), None).await;
    let (sender, content) = channel_body();
    tokio::spawn(async move {
        // More than the socket buffers on the way can hold.
        let chunk = Bytes::from(vec![b'x'; 64 * 1024]);
        while sender.send(Frame::data(chunk.clone())).await.is_ok() {}
    });
    let upload = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header("host", "a.example.org")
        .body(content)
        .unwrap();

    let response = send(proxy, upload).await;

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(exposes(
        &state,
        &upstream("errors_total", backend, r#"kind="timeout""#, 1)
    ));
}

// ---------------------------------------------------------------------------
// gRPC
// ---------------------------------------------------------------------------

/// A gRPC call over HTTP/2 to `proxy`, with `message` as its body.
fn grpc_call(message: &'static str) -> Request<BoxBody> {
    Request::builder()
        .method(Method::POST)
        .uri("http://a.example.org/pkg.Service/Method")
        .version(Version::HTTP_2)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(body::full(message))
        .unwrap()
}

/// A gRPC backend answering `delay` after a call with its own body and
/// `grpc-status: 0` in the trailers, after a `te` header line telling what
/// the call asked for.
async fn grpc_backend(delay: Duration) -> SocketAddr {
    backend(move |request: Request<Incoming>| async move {
        tokio::time::sleep(delay).await;
        let te = request
            .headers()
            .get("te")
            .map(|value| value.to_str().unwrap().to_string())
            .unwrap_or_default();
        let message = request.into_body().collect().await.unwrap().to_bytes();
        let (sender, content) = channel_body();
        tokio::spawn(async move {
            let mut text = format!("te={te};");
            text.push_str(&String::from_utf8_lossy(&message));
            sender.send(Frame::data(Bytes::from(text))).await.unwrap();
            let mut trailers = HeaderMap::new();
            trailers.insert("grpc-status", HeaderValue::from_static("0"));
            sender.send(Frame::trailers(trailers)).await.unwrap();
        });
        let mut response = Response::new(content);
        response
            .headers_mut()
            .insert("content-type", HeaderValue::from_static("application/grpc"));
        response
    })
    .await
}

#[tokio::test]
async fn relays_a_grpc_call_with_its_trailers_to_an_h2c_pool() {
    let (proxy, state) = forwarding(pool(Scheme::H2c, &[grpc_backend(Duration::ZERO).await])).await;

    let response = send_h2(proxy, grpc_call("hello")).await;
    let collected = response.into_body().collect().await.unwrap();

    assert_eq!(collected.trailers().unwrap()["grpc-status"], "0");
    assert_eq!(collected.to_bytes(), "te=trailers;hello");
    wait_for_metric(
        &state,
        r#"gfe_grpc_responses_total{listener="http",vhost="none",route="none",grpc_status="0"} 1"#,
    )
    .await;
}

#[tokio::test]
async fn a_grpc_call_silent_longer_than_upstream_first_byte_is_not_cut() {
    let backend = grpc_backend(Duration::from_millis(150)).await;
    let config = config_with_timeouts(Duration::from_millis(50), Duration::from_millis(50));
    let (proxy, _) = forwarding_with(&config, pool(Scheme::H2c, &[backend]), None).await;

    let response = send_h2(proxy, grpc_call("hello")).await;
    let collected = response.into_body().collect().await.unwrap();

    assert_eq!(collected.trailers().unwrap()["grpc-status"], "0");
}

#[tokio::test]
async fn fails_a_grpc_call_to_an_unreachable_backend_as_unavailable() {
    let (proxy, _) = forwarding(pool(Scheme::H2c, &[closed_port()])).await;

    let response = send_h2(proxy, grpc_call("hello")).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["grpc-status"], "14");
    assert_eq!(
        response.headers()["grpc-message"],
        "gfe: upstream_connect_refused"
    );
}

// ---------------------------------------------------------------------------
// Backends over TLS
// ---------------------------------------------------------------------------

fn trusting(ca_pem: &[u8]) -> NodeConfig {
    let mut config = node_config();
    config.upstream.extra_ca_file = Some(temp_file(ca_pem));
    config
}

#[tokio::test]
async fn sends_requests_to_an_https_pool_over_http1() {
    let (backend, ca) = tls_backend(&[b"h2", b"http/1.1"]).await;
    let config = trusting(&ca);
    let (proxy, _) = forwarding_with(&config, pool(Scheme::Https, &[backend]), None).await;

    let response = send(proxy, get("a.example.org", "/")).await;

    assert_eq!(response.status(), StatusCode::OK);
    let seen = text(response).await;
    assert!(seen.starts_with("GET /"), "{seen}");
    assert!(seen.contains("HTTP/1.1"), "{seen}");
    assert_eq!(header_line(&seen, "host"), Some("a.example.org"));
}

#[tokio::test]
async fn refuses_a_backend_certificate_it_does_not_trust() {
    let (backend, _) = tls_backend(&[b"http/1.1"]).await;
    let (proxy, state) = forwarding(pool(Scheme::Https, &[backend])).await;
    let (logs, _capturing) = Logs::capture();

    let response = send(proxy, get("a.example.org", "/")).await;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(logs.access_event().await["error"], "upstream_tls");
    assert!(exposes(
        &state,
        &upstream("errors_total", backend, r#"kind="tls""#, 2)
    ));
}

#[tokio::test]
async fn a_grpc_call_to_an_https_backend_without_http2_fails_as_other() {
    // v1.1.0 reported a backend that would not speak HTTP/2 as `other`.
    let (backend, ca) = tls_backend(&[b"http/1.1"]).await;
    let config = trusting(&ca);
    let (proxy, state) = forwarding_with(&config, pool(Scheme::Https, &[backend]), None).await;

    let response = send_h2(proxy, grpc_call("hello")).await;

    assert_eq!(response.headers()["grpc-status"], "14");
    assert_eq!(response.headers()["grpc-message"], "gfe: upstream_error");
    assert!(exposes(
        &state,
        &upstream("errors_total", backend, r#"kind="other""#, 1)
    ));
}

#[tokio::test]
async fn a_grpc_call_to_an_https_backend_without_alpn_fails_as_other() {
    let (backend, ca) = tls_backend(&[]).await;
    let config = trusting(&ca);
    let (proxy, _) = forwarding_with(&config, pool(Scheme::Https, &[backend]), None).await;

    let response = send_h2(proxy, grpc_call("hello")).await;

    assert_eq!(response.headers()["grpc-message"], "gfe: upstream_error");
}

// ---------------------------------------------------------------------------
// Selection and quotas
// ---------------------------------------------------------------------------

#[tokio::test]
async fn answers_503_when_no_backend_is_healthy() {
    let backend = describing_backend().await;
    let (proxy, state) = forwarding(pool(Scheme::Http, &[backend])).await;
    state
        .health()
        .set("127.0.0.1", backend.port(), HealthStatus::Unhealthy);

    let response = send(proxy, get("a.example.org", "/")).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(text(response).await.starts_with("503 no healthy upstream"));
    assert!(exposes(&state, "gfe_no_healthy_upstream_total 1"));
}

#[tokio::test]
async fn a_draining_backend_gets_no_new_request() {
    let draining = describing_backend().await;
    let serving = backend(|_request| async { Response::new(body::full("serving")) }).await;
    let (proxy, state) = forwarding(pool(Scheme::Http, &[draining, serving])).await;
    state
        .health()
        .set("127.0.0.1", draining.port(), HealthStatus::Draining);

    for _ in 0..4 {
        let response = send(proxy, get("a.example.org", "/")).await;
        assert_eq!(text(response).await, "serving");
    }
}

#[tokio::test]
async fn ring_hash_keeps_a_client_on_one_backend() {
    let a = backend(|_request| async { Response::new(body::full("a")) }).await;
    let b = backend(|_request| async { Response::new(body::full("b")) }).await;
    let ring = pool_of(pool_config(Scheme::Http, LbPolicy::RingHash, &[a, b], None));
    let (proxy, _) = forwarding(ring).await;

    let mut answers = Vec::new();
    for _ in 0..4 {
        answers.push(text(send(proxy, get("a.example.org", "/")).await).await);
    }

    answers.dedup();
    assert_eq!(answers.len(), 1, "{answers:?}");
}

#[tokio::test]
async fn answers_503_when_the_pool_has_max_in_flight_requests() {
    let slow = backend_answering_after(Duration::from_millis(300)).await;
    let limited = pool_of(pool_config(
        Scheme::Http,
        LbPolicy::RoundRobin,
        &[slow],
        Some(1),
    ));
    let (proxy, state) = forwarding(limited).await;

    let first = tokio::spawn(send(proxy, get("a.example.org", "/")));
    wait_for_metric(
        &state,
        &format!(r#"gfe_upstream_requests_in_flight{{pool="pool",backend="{slow}"}} 1"#),
    )
    .await;
    let second = send(proxy, get("a.example.org", "/")).await;

    assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(text(second).await.starts_with("503 upstream pool full"));
    assert!(exposes(
        &state,
        r#"gfe_upstream_pool_full_total{pool="pool"} 1"#
    ));
    assert_eq!(first.await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn answers_503_at_the_upstream_connection_limit_without_retrying() {
    let slow = backend_answering_after(Duration::from_millis(300)).await;
    let mut config = node_config();
    config.limits.max_upstream_connections = 1;
    let (proxy, state) = forwarding_with(&config, pool(Scheme::Http, &[slow]), None).await;
    let (logs, _capturing) = Logs::capture();

    let first = tokio::spawn(send(proxy, get("a.example.org", "/first")));
    wait_for_metric(
        &state,
        &format!(r#"gfe_upstream_requests_in_flight{{pool="pool",backend="{slow}"}} 1"#),
    )
    .await;
    let second = send(proxy, get("a.example.org", "/second")).await;

    assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        text(second)
            .await
            .starts_with("503 upstream connection limit")
    );
    assert_eq!(first.await.unwrap().status(), StatusCode::OK);
    let refused = logs
        .access_events()
        .into_iter()
        .find(|event| event["path"] == "/second")
        .unwrap();
    assert_eq!(refused["error"], "upstream_connection_limit");
    assert_eq!(refused["attempts"], 1);
    assert!(exposes(
        &state,
        &upstream("errors_total", slow, r#"kind="connection_limit""#, 1)
    ));
    // Not the backend's failure.
    assert!(!exposes(&state, "gfe_upstream_connect_errors_total 1"));
    assert!(!exposes(&state, r#"status="502""#));
}

// ---------------------------------------------------------------------------
// The response, for the client
// ---------------------------------------------------------------------------

#[test]
fn every_scheme_is_spoken_as_configured() {
    assert_eq!(client_scheme(Scheme::Http), ClientScheme::Http);
    assert_eq!(client_scheme(Scheme::Https), ClientScheme::Https);
    assert_eq!(client_scheme(Scheme::H2c), ClientScheme::H2c);
}
