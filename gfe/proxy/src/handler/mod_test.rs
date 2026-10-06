use super::*;
use crate::handler::test_support::*;
use crate::routing::RouteTable;
use gfe_config::{
    DynamicConfig, FixedAction, LbPolicy, ListenerId, RedirectAction, Route, RouteId, Scheme,
    UpstreamPool,
};
use netkit_http::body::{self, BodyExt};
use netkit_http::{HeaderValue, Method, StatusCode, Version};
use netkit_load_balancing::PoolSet;
use netkit_tls::TlsInfo;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn route(id: &str, host: &str, path: &str, action: RouteAction) -> Route {
    Route {
        id: RouteId(id.into()),
        listener: ListenerId("http".into()),
        host: host.into(),
        path_prefix: path.into(),
        action,
    }
}

fn forward_to(pool: &str) -> RouteAction {
    RouteAction::Forward(pool.into())
}

/// A config with `routes` on listener `http`, forwarding to `pools`.
fn config(routes: Vec<Route>, pools: Vec<UpstreamPool>) -> DynamicConfig {
    DynamicConfig {
        routes,
        pools,
        ..Default::default()
    }
}

/// A config forwarding `a.example.org` (route `web`) to `backend`.
fn forwarding_to(backend: SocketAddr) -> DynamicConfig {
    config(
        vec![route("web", "a.example.org", "/", forward_to("pool"))],
        vec![pool_config(
            Scheme::Http,
            LbPolicy::RoundRobin,
            &[backend],
            None,
        )],
    )
}

/// A node serving `config` through a [`Proxy`], its connections told they
/// negotiated `tls`.
async fn proxy_with(config: &DynamicConfig, tls: Option<TlsInfo>) -> (SocketAddr, Arc<State>) {
    let state = state();
    state.swap(
        RouteTable::compile(config),
        PoolSet::build(&crate::reload::pool_specs(&config.pools)).unwrap(),
    );
    let address = serve(Arc::new(Proxy::new(Arc::clone(&state))), tls).await;
    (address, state)
}

/// A node serving `config` over cleartext.
async fn proxy(config: &DynamicConfig) -> (SocketAddr, Arc<State>) {
    proxy_with(config, None).await
}

/// A request for `path` without a `Host` header.
fn without_host(path: &str) -> Request<BoxBody> {
    Request::builder().uri(path).body(body::empty()).unwrap()
}

fn requests_total(vhost: &str, route: &str, status: u16) -> String {
    format!(
        r#"gfe_requests_total{{listener="http",vhost="{vhost}",route="{route}",status="{status}"}} 1"#
    )
}

// ---------------------------------------------------------------------------
// Which host, which route
// ---------------------------------------------------------------------------

#[tokio::test]
async fn proxies_a_request_to_its_routes_backend_and_counts_it_under_the_route() {
    let (proxy, state) = proxy(&forwarding_to(describing_backend().await)).await;

    let response = send(proxy, get("a.example.org", "/x")).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(text(response).await.starts_with("GET /x HTTP/1.1"));
    wait_for_metric(&state, &requests_total("a.example.org", "web", 200)).await;
}

#[tokio::test]
async fn unmatched_host_is_answered_404_no_route() {
    let (proxy, state) = proxy(&forwarding_to(describing_backend().await)).await;
    let (logs, _capturing) = Logs::capture();

    let response = send(proxy, get("b.example.org", "/")).await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(response.headers().contains_key("x-request-id"));
    assert!(text(response).await.starts_with("404 no route"));
    let event = logs.access_event().await;
    assert_eq!(event["error"], "no_route");
    assert_eq!(event["host"], "b.example.org");
    assert_eq!(event["route"], "none");
    assert!(exposes(&state, "gfe_no_route_total 1"));
    assert!(exposes(&state, &requests_total("none", "none", 404)));
}

#[tokio::test]
async fn a_target_and_host_header_that_disagree_are_answered_400() {
    let (proxy, _) = proxy(&forwarding_to(describing_backend().await)).await;
    let (logs, _capturing) = Logs::capture();
    let request = Request::builder()
        .uri("http://public.example.org/")
        .header("host", "internal.example.org")
        .body(body::empty())
        .unwrap();

    let response = send(proxy, request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let event = logs.access_event().await;
    assert_eq!(event["error"], "host_conflict");
    assert_eq!(event["host"], "public.example.org");
}

#[tokio::test]
async fn serves_a_target_differing_from_the_host_header_in_case_only() {
    // Pingora answered 400 to this; v1.1.0 serves it.
    let (proxy, _) = proxy(&forwarding_to(describing_backend().await)).await;
    let request = Request::builder()
        .uri("http://A.example.org:80/")
        .header("host", "a.example.org")
        .body(body::empty())
        .unwrap();

    let response = send(proxy, request).await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_cleartext_request_without_a_host_is_answered_400() {
    let (proxy, _) = proxy(&forwarding_to(describing_backend().await)).await;
    let (logs, _capturing) = Logs::capture();

    let response = send(proxy, without_host("/")).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(logs.access_event().await["error"], "host_missing");
}

#[tokio::test]
async fn takes_the_host_from_the_sni_when_the_request_names_none() {
    let config = forwarding_to(describing_backend().await);
    let (proxy, _) = proxy_with(&config, Some(tls_info("a.example.org"))).await;

    let response = send(proxy, without_host("/")).await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_host_the_certificate_of_the_sni_does_not_cover_is_answered_421() {
    let config = forwarding_to(describing_backend().await);
    let (proxy, _) = proxy_with(&config, Some(tls_info("b.example.org"))).await;

    let response = send(proxy, get("a.example.org", "/")).await;

    assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn serves_an_http10_request_without_a_host_from_the_catch_all_route() {
    let fixed = RouteAction::Fixed(FixedAction {
        status: 200,
        body: "catch-all".into(),
    });
    let (proxy, _) = proxy(&config(vec![route("all", "*", "/", fixed)], vec![])).await;
    let mut stream = TcpStream::connect(proxy).await.unwrap();

    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await.unwrap();

    assert!(answer.contains(" 200 "), "{answer}");
    assert!(answer.ends_with("catch-all"), "{answer}");
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_redirect_names_the_same_host_and_path_under_its_scheme() {
    let redirect = RouteAction::Redirect(RedirectAction {
        scheme: "https".into(),
        status: 301,
    });
    let (proxy, _) = proxy(&config(vec![route("tls", "*", "/", redirect)], vec![])).await;

    let response = send(proxy, get("a.example.org", "/path?q=1")).await;

    assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        response.headers()["location"],
        "https://a.example.org/path?q=1"
    );
    assert!(response.headers().contains_key("x-request-id"));
}

#[tokio::test]
async fn a_fixed_action_answers_without_a_backend() {
    let fixed = RouteAction::Fixed(FixedAction {
        status: 503,
        body: "maintenance".into(),
    });
    let (proxy, state) = proxy(&config(vec![route("down", "*", "/", fixed)], vec![])).await;

    let response = send(proxy, get("a.example.org", "/")).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(text(response).await, "maintenance");
    wait_for_metric(&state, &requests_total("*", "down", 503)).await;
}

#[tokio::test]
async fn a_route_to_a_pool_the_config_lacks_is_answered_502() {
    let (proxy, _) = proxy(&config(
        vec![route("web", "*", "/", forward_to("missing"))],
        vec![],
    ))
    .await;
    let (logs, _capturing) = Logs::capture();

    let response = send(proxy, get("a.example.org", "/")).await;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(logs.access_event().await["error"], "pool_not_found");
}

// ---------------------------------------------------------------------------
// gRPC
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fails_a_grpc_call_without_a_route_as_unimplemented() {
    let (proxy, state) = proxy(&config(vec![], vec![])).await;
    let call = Request::builder()
        .method(Method::POST)
        .uri("http://a.example.org/pkg.Service/Method")
        .version(Version::HTTP_2)
        .header("content-type", "application/grpc")
        .body(body::empty())
        .unwrap();

    let response = send_h2(proxy, call).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["grpc-status"], "12");
    assert_eq!(response.headers()["grpc-message"], "gfe: no_route");
    wait_for_metric(
        &state,
        r#"gfe_grpc_responses_total{listener="http",vhost="none",route="none",grpc_status="12"} 1"#,
    )
    .await;
    assert!(exposes(&state, &requests_total("none", "none", 200)));
}

// ---------------------------------------------------------------------------
// Accounting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_access_event_describes_a_proxied_request() {
    let backend = describing_backend().await;
    let (proxy, _) = proxy(&forwarding_to(backend)).await;
    let (logs, _capturing) = Logs::capture();
    let mut request = get("a.example.org", "/x");
    request
        .headers_mut()
        .insert("user-agent", HeaderValue::from_static("test/1"));

    let response = send(proxy, request).await;
    let _ = text(response).await;

    let event = logs.access_event().await;
    assert_eq!(event["status"], 200);
    assert_eq!(event["route"], "web");
    assert_eq!(event["pool"], "pool");
    assert_eq!(event["backend"], backend.to_string());
    assert_eq!(event["attempts"], 1);
    assert_eq!(event["client"], "127.0.0.1");
    assert_eq!(event["listener"], "http");
    assert_eq!(event["proto"], "http");
    assert_eq!(event["method"], "GET");
    assert_eq!(event["path"], "/x");
    assert_eq!(event["user_agent"], "test/1");
    assert_eq!(event["termination"], "complete");
    assert!(event["upstream_ttfb_ms"].is_number(), "{event}");
    assert!(event.get("error").is_none(), "{event}");
}

#[tokio::test]
async fn reports_a_request_abandoned_before_the_response_once_as_499() {
    let slow = backend_answering_after(Duration::from_secs(5)).await;
    let (proxy, state) = proxy(&forwarding_to(slow)).await;
    let (logs, _capturing) = Logs::capture();
    let mut stream = TcpStream::connect(proxy).await.unwrap();

    stream
        .write_all(b"GET /x HTTP/1.1\r\nhost: a.example.org\r\n\r\n")
        .await
        .unwrap();
    wait_for_metric(
        &state,
        &format!(r#"gfe_upstream_requests_in_flight{{pool="pool",backend="{slow}"}} 1"#),
    )
    .await;
    drop(stream);

    let event = logs.access_event().await;
    assert_eq!(event["status"], 499);
    assert_eq!(event["termination"], "client_abort");
    assert_eq!(event["backend"], slow.to_string());
    wait_for_metric(
        &state,
        r#"gfe_requests_aborted_total{listener="http",vhost="a.example.org",route="web",by="client"} 1"#,
    )
    .await;
    wait_for_metric(
        &state,
        &format!(r#"gfe_upstream_requests_in_flight{{pool="pool",backend="{slow}"}} 0"#),
    )
    .await;
    assert_eq!(logs.access_events().len(), 1);
}

#[tokio::test]
async fn reports_a_client_that_leaves_in_the_middle_of_a_response_as_a_client_abort() {
    let backend = backend(|_request| async {
        let (sender, content) = channel_body();
        tokio::spawn(async move {
            let chunk = netkit_http::Bytes::from_static(b"chunk");
            while sender
                .send(netkit_http::body::Frame::data(chunk.clone()))
                .await
                .is_ok()
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        Response::new(content)
    })
    .await;
    let (proxy, _) = proxy(&forwarding_to(backend)).await;
    let (logs, _capturing) = Logs::capture();

    let mut response = send(proxy, get("a.example.org", "/")).await;
    response.body_mut().frame().await.unwrap().unwrap();
    drop(response);

    let event = logs.access_event().await;
    assert_eq!(event["status"], 200);
    assert_eq!(event["termination"], "client_abort");
}

#[tokio::test]
async fn counts_every_request_of_a_keep_alive_connection_once() {
    let (proxy, state) = proxy(&forwarding_to(describing_backend().await)).await;
    let stream = TcpStream::connect(proxy).await.unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(connection);

    for _ in 0..3 {
        let response = sender
            .send_request(get("a.example.org", "/"))
            .await
            .unwrap();
        response.into_body().collect().await.unwrap();
    }

    wait_for_metric(
        &state,
        r#"gfe_requests_total{listener="http",vhost="a.example.org",route="web",status="200"} 3"#,
    )
    .await;
    wait_for_metric(&state, "gfe_requests_in_flight 0").await;
}
