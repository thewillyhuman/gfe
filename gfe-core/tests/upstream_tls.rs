//! TLS to backends: certificates verified against the trusted roots and the
//! backend's name, a client certificate presented when configured, and the
//! HTTP version ALPN settles on.

mod common;

use common::*;
use gfe_config::Scheme;
use std::net::SocketAddr;

/// A proxy forwarding `a.example.org` to the `https` backend `upstream`,
/// under `node`.
async fn https_proxy(upstream: SocketAddr, node: gfe_config::NodeConfig) -> Proxy {
    let mut cfg = forwarding_config(upstream);
    cfg.pools[0].scheme = Scheme::Https;
    Proxy::start_with(&cfg, node, None).await
}

/// A node config trusting `ca_pem` on top of the system roots.
fn trusting(ca_pem: &[u8]) -> gfe_config::NodeConfig {
    let mut node = node_config();
    node.upstream.extra_ca_file = Some(pem_file(ca_pem));
    node
}

/// Over HTTP/2 the backend would be named by `:authority`, contradicting
/// the client's host in `Host`, so an `https` pool is spoken to in HTTP/1.1.
#[tokio::test]
async fn sends_requests_to_an_https_pool_verified_against_the_extra_ca_over_http1() {
    let (upstream, ca_pem) = spawn_tls_upstream("127.0.0.1", ClientAuth::None).await;
    let proxy = https_proxy(upstream, trusting(&ca_pem)).await;

    let answer = h2_request(proxy.addr, "GET", "http://a.example.org/", "").await;

    assert_eq!(answer.status, 200, "{}", answer.body);
    assert!(
        answer
            .body
            .starts_with("version=HTTP/1.1 host=a.example.org "),
        "{}",
        answer.body
    );
}

#[tokio::test]
async fn refuses_a_backend_certificate_it_does_not_trust() {
    let (logs, _guard) = CapturedLogs::start();
    let (upstream, _) = spawn_tls_upstream("127.0.0.1", ClientAuth::None).await;
    let proxy = https_proxy(upstream, node_config()).await;

    let (status, _) = http_get(proxy.addr, "a.example.org", "/").await;
    let event = logs.access_event().await;

    assert_eq!(status, 502);
    assert_eq!(event["error"], "upstream_tls");
}

#[tokio::test]
async fn refuses_a_backend_certificate_for_another_name() {
    let (logs, _guard) = CapturedLogs::start();
    let (upstream, ca_pem) = spawn_tls_upstream("other.example.org", ClientAuth::None).await;
    let proxy = https_proxy(upstream, trusting(&ca_pem)).await;

    let (status, _) = http_get(proxy.addr, "a.example.org", "/").await;
    let event = logs.access_event().await;

    assert_eq!(status, 502);
    assert_eq!(event["error"], "upstream_tls");
    proxy
        .wait_for_metric(&format!(
            r#"gfe_upstream_errors_total{{pool="pool",backend="{upstream}",kind="tls"}} 2"#
        ))
        .await;
}

#[tokio::test]
async fn presents_the_configured_client_certificate() {
    let (client_cert, client_key, client) = certificate_files(&["gfe.example.org"]);
    let (upstream, ca_pem) = spawn_tls_upstream(
        "127.0.0.1",
        ClientAuth::Required(client.cert.pem().into_bytes()),
    )
    .await;
    let mut node = trusting(&ca_pem);
    node.upstream.client_cert_file = Some(client_cert);
    node.upstream.client_key_file = Some(client_key);
    let proxy = https_proxy(upstream, node).await;

    let (status, body) = http_get(proxy.addr, "a.example.org", "/").await;

    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn is_refused_by_a_backend_requiring_a_client_certificate_it_lacks() {
    let (_, _, client) = certificate_files(&["gfe.example.org"]);
    let (upstream, ca_pem) = spawn_tls_upstream(
        "127.0.0.1",
        ClientAuth::Required(client.cert.pem().into_bytes()),
    )
    .await;
    let proxy = https_proxy(upstream, trusting(&ca_pem)).await;

    let (status, _) = http_get(proxy.addr, "a.example.org", "/").await;

    assert_eq!(status, 502);
}

#[tokio::test]
async fn sends_grpc_calls_to_an_https_pool_over_http2_without_host() {
    let (upstream, ca_pem) = spawn_tls_upstream("127.0.0.1", ClientAuth::None).await;
    let mut cfg = grpc_config(upstream);
    cfg.pools[0].scheme = Scheme::Https;
    let proxy = Proxy::start_with(&cfg, trusting(&ca_pem), None).await;

    let call = GrpcCall::open(proxy.addr).await;

    assert_eq!(
        call.response.headers()["x-described"],
        format!("version=HTTP/2.0 host=none authority={upstream}").as_str()
    );
}

#[tokio::test]
async fn keeps_grpc_and_plain_requests_to_one_https_backend_apart() {
    let (upstream, ca_pem) = spawn_tls_upstream("127.0.0.1", ClientAuth::None).await;
    let mut cfg = grpc_config(upstream);
    cfg.pools[0].scheme = Scheme::Https;
    let proxy = Proxy::start_with(&cfg, trusting(&ca_pem), None).await;

    // A plain request leaves an HTTP/1.1 connection in the pool...
    let (_, plain) = http_get(proxy.addr, "a.example.org", "/").await;
    // ...which a gRPC call must not be given.
    let call = GrpcCall::open(proxy.addr).await;

    assert!(plain.starts_with("version=HTTP/1.1"), "{plain}");
    assert!(
        call.response.headers()["x-described"]
            .to_str()
            .unwrap()
            .starts_with("version=HTTP/2.0"),
    );
}
