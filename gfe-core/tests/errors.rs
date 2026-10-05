//! The answers GFE writes itself, as the client sees them: status,
//! `X-Request-Id`, body, and, to a gRPC call, gRPC's terms.

mod common;

use common::*;
use gfe_config::RouteAction;
use gfe_health_checking::HealthStatus;

/// A request id the client sends, which the answer must carry back.
const ID: &str = "client-id-1";

/// Check a plain synthetic answer as GFE writes it.
fn assert_synthetic(answer: &Answer, status: u16, message: &str) {
    assert_eq!(answer.status, status, "{}", answer.body);
    assert_eq!(answer.headers["x-request-id"], ID);
    assert_eq!(answer.headers["content-type"], "text/plain; charset=utf-8");
    assert_eq!(
        answer.body,
        format!("{status} {message}\nrequest-id: {ID}\n")
    );
    assert_eq!(
        answer.headers["content-length"],
        answer.body.len().to_string().as_str()
    );
    // Nothing about the engine leaks.
    assert!(
        !answer.headers.contains_key("server"),
        "{:?}",
        answer.headers
    );
}

#[tokio::test]
async fn no_route_is_a_404() {
    let proxy = Proxy::start(&fixed_response_config_for("a.example.org")).await;

    let answer = get_with(proxy.addr, "b.example.org", "/", &[("x-request-id", ID)]).await;

    assert_synthetic(&answer, 404, "no route");
}

fn fixed_response_config_for(host: &str) -> gfe_config::DynamicConfig {
    let mut cfg = fixed_response_config();
    cfg.routes[0].host = host.into();
    cfg
}

#[tokio::test]
async fn unsupported_target_and_upgrade_are_400_and_501() {
    let proxy = Proxy::start(&forwarding_config(spawn_upstream().await)).await;

    let upgrade = get_with(
        proxy.addr,
        "a.example.org",
        "/",
        &[
            ("x-request-id", ID),
            ("connection", "upgrade"),
            ("upgrade", "websocket"),
        ],
    )
    .await;
    let options = raw_exchange(
        proxy.addr,
        &format!(
            "OPTIONS * HTTP/1.1\r\nhost: a.example.org\r\nx-request-id: {ID}\r\nconnection: close\r\n\r\n"
        ),
    )
    .await;

    assert_synthetic(&upgrade, 501, "protocol upgrade not supported");
    assert!(options.starts_with("HTTP/1.1 400"), "{options}");
    assert!(
        options.ends_with(&format!(
            "400 unsupported request target\nrequest-id: {ID}\n"
        )),
        "{options}"
    );
}

#[tokio::test]
async fn pool_not_found_is_a_502() {
    let mut cfg = forwarding_config(spawn_upstream().await);
    cfg.routes[0].action = RouteAction::Forward("missing".into());
    let proxy = Proxy::start(&cfg).await;

    let answer = get_with(proxy.addr, "a.example.org", "/", &[("x-request-id", ID)]).await;

    assert_synthetic(&answer, 502, "pool not found");
}

#[tokio::test]
async fn unreachable_backend_is_a_502() {
    let proxy = Proxy::start(&forwarding_config(closed_port())).await;

    let answer = get_with(proxy.addr, "a.example.org", "/", &[("x-request-id", ID)]).await;

    assert_synthetic(&answer, 502, "upstream error");
}

#[tokio::test]
async fn no_healthy_backend_is_a_503() {
    let upstream = spawn_upstream().await;
    let proxy = Proxy::start(&forwarding_config(upstream)).await;
    proxy
        .state
        .health()
        .set("127.0.0.1", upstream.port(), HealthStatus::Unhealthy);

    let answer = get_with(proxy.addr, "a.example.org", "/", &[("x-request-id", ID)]).await;

    assert_synthetic(&answer, 503, "no healthy upstream");
}

#[tokio::test]
async fn silent_backend_is_a_504() {
    let mut node = node_config();
    node.timeouts.upstream_first_byte = std::time::Duration::from_millis(100);
    let proxy = Proxy::start_with(
        &forwarding_config(spawn_silent_upstream().await),
        node,
        None,
    )
    .await;

    let answer = get_with(proxy.addr, "a.example.org", "/", &[("x-request-id", ID)]).await;

    assert_synthetic(&answer, 504, "upstream timeout");
}

#[tokio::test]
async fn misdirected_request_is_a_421() {
    let mut cfg = fixed_response_config();
    cfg.certificates = vec![
        cert_entry(&["a.example.org"]),
        cert_entry(&["c.example.org"]),
    ];
    let proxy = Proxy::start_with(&cfg, node_config(), Some(tls_info("a.example.org"))).await;

    let answer = get_with(proxy.addr, "c.example.org", "/", &[("x-request-id", ID)]).await;

    assert_synthetic(&answer, 421, "misdirected request");
}

#[tokio::test]
async fn a_generated_request_id_is_32_hex_digits() {
    let proxy = Proxy::start(&fixed_response_config_for("a.example.org")).await;

    let answer = get_with(proxy.addr, "b.example.org", "/", &[]).await;

    let id = answer.headers["x-request-id"].to_str().unwrap();
    assert_eq!(id.len(), 32);
    assert!(
        answer.body.ends_with(&format!("request-id: {id}\n")),
        "{}",
        answer.body
    );
}

#[tokio::test]
async fn a_failed_grpc_call_is_answered_trailers_only_in_grpc_terms() {
    let proxy = Proxy::start(&grpc_config(closed_port())).await;

    let mut sender = h2_sender(proxy.addr).await;
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    let req = hyper::Request::builder()
        .method("POST")
        .uri("http://grpc.example.org/echo.Echo/Unary")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("x-request-id", ID)
        .body(ChannelBody(rx))
        .unwrap();
    let answer = collect(sender.send_request(req).await.unwrap()).await;

    assert_eq!(answer.status, 200);
    assert_eq!(answer.headers["content-type"], "application/grpc");
    assert_eq!(answer.headers["grpc-status"], "14");
    assert_eq!(
        answer.headers["grpc-message"],
        "gfe: upstream_connect_refused"
    );
    assert_eq!(answer.headers["x-request-id"], ID);
    assert_eq!(answer.body, "");
}
