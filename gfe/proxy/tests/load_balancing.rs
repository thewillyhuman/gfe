//! Which backend of a pool gets a request: the policies, over the healthy
//! backends only.

mod common;

use bytes::Bytes;
use common::*;
use gfe_config::{LbPolicy, Scheme};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response};
use netkit_health_checking::HealthStatus;
use std::net::SocketAddr;
use std::time::Duration;

/// A backend answering with its own name, after `delay`.
async fn spawn_named(name: &'static str, delay: Duration) -> SocketAddr {
    serve_http1(move |_req: Request<Incoming>| async move {
        tokio::time::sleep(delay).await;
        Response::new(Full::new(Bytes::from(name)))
    })
    .await
}

/// A proxy forwarding `a.example.org` to `backends` with `policy`.
async fn proxy_over(policy: LbPolicy, backends: &[SocketAddr]) -> Proxy {
    let mut cfg = forwarding_config(backends[0]);
    cfg.pools[0] = pool("pool", Scheme::Http, backends);
    cfg.pools[0].lb_policy = policy;
    Proxy::start(&cfg).await
}

async fn answer_of(proxy: &Proxy) -> String {
    let (status, body) = http_get(proxy.addr, "a.example.org", "/").await;
    assert_eq!(status, 200, "{body}");
    body
}

#[tokio::test]
async fn round_robin_alternates_between_backends() {
    let a = spawn_named("a", Duration::ZERO).await;
    let b = spawn_named("b", Duration::ZERO).await;
    let proxy = proxy_over(LbPolicy::RoundRobin, &[a, b]).await;

    let mut answers = Vec::new();
    for _ in 0..4 {
        answers.push(answer_of(&proxy).await);
    }

    assert_eq!(
        answers.iter().filter(|a| *a == "a").count(),
        2,
        "{answers:?}"
    );
    assert_eq!(
        answers.iter().filter(|a| *a == "b").count(),
        2,
        "{answers:?}"
    );
    assert_ne!(answers[0], answers[1]);
}

#[tokio::test]
async fn ring_hash_keeps_a_client_on_one_backend() {
    let a = spawn_named("a", Duration::ZERO).await;
    let b = spawn_named("b", Duration::ZERO).await;
    let proxy = proxy_over(LbPolicy::RingHash, &[a, b]).await;

    let first = answer_of(&proxy).await;
    for _ in 0..5 {
        assert_eq!(answer_of(&proxy).await, first);
    }
}

#[tokio::test]
async fn least_request_avoids_the_busy_backend() {
    let slow = spawn_named("slow", Duration::from_millis(800)).await;
    let fast = spawn_named("fast", Duration::ZERO).await;
    let proxy = proxy_over(LbPolicy::LeastRequest, &[slow, fast]).await;
    let busy_line = format!(r#"gfe_upstream_requests_in_flight{{pool="pool",backend="{slow}"}} 1"#);

    // Make the slow backend busy: requests go to it until one is in flight
    // there.
    let addr = proxy.addr;
    let mut held = Vec::new();
    while !proxy.metrics().contains(&busy_line) {
        held.push(tokio::spawn(async move {
            http_get(addr, "a.example.org", "/").await
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(held.len() < 50, "the slow backend never became busy");
    }

    for _ in 0..3 {
        assert_eq!(answer_of(&proxy).await, "fast");
    }
}

#[tokio::test]
async fn only_healthy_backends_receive_requests() {
    let a = spawn_named("a", Duration::ZERO).await;
    let b = spawn_named("b", Duration::ZERO).await;
    let proxy = proxy_over(LbPolicy::RoundRobin, &[a, b]).await;
    let health = proxy.state.health();

    health.set("127.0.0.1", a.port(), HealthStatus::Unhealthy);
    for _ in 0..4 {
        assert_eq!(answer_of(&proxy).await, "b");
    }

    health.set("127.0.0.1", a.port(), HealthStatus::Healthy);
    health.set("127.0.0.1", b.port(), HealthStatus::Draining);
    for _ in 0..4 {
        assert_eq!(answer_of(&proxy).await, "a");
    }
}

#[tokio::test]
async fn answers_503_when_no_backend_is_healthy() {
    let (logs, _guard) = CapturedLogs::start();
    let a = spawn_named("a", Duration::ZERO).await;
    let proxy = proxy_over(LbPolicy::RoundRobin, &[a]).await;
    proxy
        .state
        .health()
        .set("127.0.0.1", a.port(), HealthStatus::Unhealthy);

    let (status, body) = http_get(proxy.addr, "a.example.org", "/").await;
    let event = logs.access_event().await;

    assert_eq!(status, 503);
    assert!(body.starts_with("503 no healthy upstream"), "{body}");
    assert_eq!(event["error"], "no_healthy_upstream");
    assert_eq!(event["pool"], "pool");
    proxy
        .wait_for_metric("gfe_no_healthy_upstream_total 1")
        .await;
}
