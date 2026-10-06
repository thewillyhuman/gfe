//! Which route a request takes, and the host rules that come first.

mod common;

use common::*;
use gfe_config::{FixedAction, RedirectAction, RouteAction};

/// Routes for `host` answering each with a fixed body naming the route.
fn fixed(id: &str, host: &str, path: &str) -> gfe_config::Route {
    route(
        id,
        host,
        path,
        RouteAction::Fixed(FixedAction {
            status: 200,
            body: id.into(),
        }),
    )
}

fn config(routes: Vec<gfe_config::Route>) -> gfe_config::DynamicConfig {
    gfe_config::DynamicConfig {
        listeners: vec![http_listener()],
        routes,
        ..Default::default()
    }
}

#[tokio::test]
async fn proxies_a_request_to_its_routes_backend() {
    let upstream = spawn_upstream().await;
    let proxy = Proxy::start(&forwarding_config(upstream)).await;

    let (status, body) = http_get(proxy.addr, "a.example.org", "/").await;

    assert_eq!(status, 200, "{body}");
    assert!(body.starts_with("upstream-ok"), "{body}");
}

#[tokio::test]
async fn exact_host_beats_wildcard_and_catch_all() {
    let proxy = Proxy::start(&config(vec![
        fixed("any", "*", "/"),
        fixed("wild", "*.example.org", "/"),
        fixed("exact", "api.example.org", "/"),
    ]))
    .await;

    let (_, exact) = http_get(proxy.addr, "api.example.org", "/").await;
    let (_, wild) = http_get(proxy.addr, "www.example.org", "/").await;
    let (_, any) = http_get(proxy.addr, "elsewhere.org", "/").await;

    assert_eq!(exact, "exact");
    assert_eq!(wild, "wild");
    assert_eq!(any, "any");
}

#[tokio::test]
async fn wildcard_route_matches_only_subdomains_of_its_suffix() {
    let proxy = Proxy::start(&config(vec![fixed("wild", "*.example.org", "/")])).await;

    let (subdomain, _) = http_get(proxy.addr, "api.example.org", "/").await;
    let (lookalike, _) = http_get(proxy.addr, "fooexample.org", "/").await;
    let (deeper, _) = http_get(proxy.addr, "a.b.example.org", "/").await;

    assert_eq!(subdomain, 200);
    assert_eq!(lookalike, 404);
    assert_eq!(deeper, 404);
}

#[tokio::test]
async fn longest_path_prefix_wins() {
    let proxy = Proxy::start(&config(vec![
        fixed("root", "a.example.org", "/"),
        fixed("api", "a.example.org", "/api/"),
    ]))
    .await;

    let (_, api) = http_get(proxy.addr, "a.example.org", "/api/users").await;
    let (_, root) = http_get(proxy.addr, "a.example.org", "/apix").await;

    assert_eq!(api, "api");
    assert_eq!(root, "root");
}

#[tokio::test]
async fn exact_path_matches_its_route() {
    let proxy = Proxy::start(&config(vec![
        fixed("root", "a.example.org", "/"),
        fixed("login", "a.example.org", "/login"),
    ]))
    .await;

    let (_, login) = http_get(proxy.addr, "a.example.org", "/login").await;
    let (_, below) = http_get(proxy.addr, "a.example.org", "/login/x").await;
    let (_, beside) = http_get(proxy.addr, "a.example.org", "/loginx").await;

    assert_eq!(login, "login");
    assert_eq!(below, "login");
    assert_eq!(beside, "root");
}

#[tokio::test]
async fn unmatched_host_returns_404_no_route() {
    let (logs, _guard) = CapturedLogs::start();
    let proxy = Proxy::start(&config(vec![fixed("r", "a.example.org", "/")])).await;

    let (status, body) = http_get(proxy.addr, "unknown.example.org", "/").await;
    let event = logs.access_event().await;

    assert_eq!(status, 404);
    assert!(body.starts_with("404 no route"), "{body}");
    assert_eq!(event["error"], "no_route");
    assert_eq!(event["route"], "none");
    proxy.wait_for_metric("gfe_no_route_total 1").await;
}

#[tokio::test]
async fn redirect_action_names_the_same_host_and_path() {
    let proxy = Proxy::start(&config(vec![route(
        "redir",
        "*",
        "/",
        RouteAction::Redirect(RedirectAction {
            scheme: "https".into(),
            status: 308,
        }),
    )]))
    .await;

    let answer = get_with(proxy.addr, "a.example.org", "/path?q=1", &[]).await;

    assert_eq!(answer.status, 308);
    assert_eq!(answer.headers["location"], "https://a.example.org/path?q=1");
    assert!(answer.headers.contains_key("x-request-id"));
}

#[tokio::test]
async fn fixed_action_answers_without_a_backend() {
    let proxy = Proxy::start(&fixed_response_config()).await;

    let answer = get_with(proxy.addr, "a.example.org", "/", &[("x-request-id", "abc")]).await;

    assert_eq!(answer.status, 200);
    assert_eq!(answer.body, "ok");
    assert_eq!(answer.headers["x-request-id"], "abc");
}

#[tokio::test]
async fn answers_400_when_the_target_and_host_header_disagree() {
    let (logs, _guard) = CapturedLogs::start();
    let proxy = Proxy::start(&fixed_response_config()).await;

    let response = raw_exchange(
        proxy.addr,
        "GET http://public.example.org/ HTTP/1.1\r\nhost: internal.example.org\r\n\
         connection: close\r\n\r\n",
    )
    .await;
    let event = logs.access_event().await;

    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert_eq!(event["status"], 400);
    assert_eq!(event["error"], "host_conflict");
}

/// The authority and `Host` are compared as hosts: case and the default
/// port do not make them disagree.
#[tokio::test]
async fn serves_absolute_form_target_that_agrees_with_the_host_header() {
    let proxy = Proxy::start(&fixed_response_config()).await;

    let response = raw_exchange(
        proxy.addr,
        "GET http://Public.example.org:80/ HTTP/1.1\r\nhost: public.example.org\r\n\
         connection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}

#[tokio::test]
async fn answers_400_to_a_cleartext_request_without_a_host() {
    let (logs, _guard) = CapturedLogs::start();
    let proxy = Proxy::start(&fixed_response_config()).await;

    let response = raw_exchange(proxy.addr, "GET / HTTP/1.1\r\nconnection: close\r\n\r\n").await;
    let event = logs.access_event().await;

    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert_eq!(event["error"], "host_missing");
    assert_eq!(event["status"], 400);
}

#[tokio::test]
async fn serves_an_http10_request_without_a_host_from_the_catch_all_route() {
    let proxy = Proxy::start(&fixed_response_config()).await;

    // Shorter than the HTTP/2 preface: the protocol is told by what arrives,
    // not by waiting for 24 bytes.
    let response = raw_exchange(proxy.addr, "GET / HTTP/1.0\r\n\r\n").await;

    assert!(response.starts_with("HTTP/1.0 200"), "{response}");
}

/// One certificate for `a.example.org` and `b.example.org`, another for
/// `c.example.org`, on a listener answering every request itself.
fn two_certificates_config() -> gfe_config::DynamicConfig {
    let mut cfg = fixed_response_config();
    cfg.certificates = vec![
        cert_entry(&["a.example.org", "b.example.org"]),
        cert_entry(&["c.example.org"]),
    ];
    cfg
}

#[tokio::test]
async fn takes_the_host_from_the_sni_when_the_request_names_none() {
    let mut cfg = config(vec![fixed("a", "a.example.org", "/")]);
    cfg.certificates = vec![cert_entry(&["a.example.org"])];
    let proxy = Proxy::start_with(&cfg, node_config(), Some(tls_info("a.example.org"))).await;

    let response = raw_exchange(proxy.addr, "GET / HTTP/1.1\r\nconnection: close\r\n\r\n").await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("\r\n\r\na"), "{response}");
}

#[tokio::test]
async fn serves_a_host_covered_by_the_certificate_of_the_sni() {
    let proxy = Proxy::start_with(
        &two_certificates_config(),
        node_config(),
        Some(tls_info("a.example.org")),
    )
    .await;

    let (status, _) = http_get(proxy.addr, "b.example.org", "/").await;

    assert_eq!(status, 200);
}

#[tokio::test]
async fn answers_421_to_a_host_covered_by_another_certificate_than_the_sni() {
    let (logs, _guard) = CapturedLogs::start();
    let proxy = Proxy::start_with(
        &two_certificates_config(),
        node_config(),
        Some(tls_info("a.example.org")),
    )
    .await;

    let (status, body) = http_get(proxy.addr, "c.example.org", "/").await;
    let event = logs.access_event().await;

    assert_eq!(status, 421);
    assert!(body.starts_with("421 misdirected request"), "{body}");
    assert_eq!(event["error"], "misdirected_request");
    assert_eq!(event["host"], "c.example.org");
}
