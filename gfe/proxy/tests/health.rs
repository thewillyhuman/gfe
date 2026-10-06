//! Health checking by a whole front end: the probes of the backends it is
//! configured with decide which of them get requests.

mod common;

use bytes::Bytes;
use common::node::Node;
use common::{ChannelBody, forwarding_config, http_get, serve_h2c, serve_http1};
use gfe_config::{HealthCheckConfig, ProbeType, Scheme};
use http_body_util::Full;
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

/// A check every 100 ms that changes a backend's state on the first probe
/// that says so.
fn quick_check(probe_type: ProbeType) -> HealthCheckConfig {
    HealthCheckConfig {
        probe_type,
        interval: Duration::from_millis(100),
        timeout: Duration::from_secs(1),
        healthy_threshold: 1,
        unhealthy_threshold: 1,
        path: "/healthz".into(),
        expected_status: 200,
        drain_status: Some(418),
    }
}

/// A backend answering `/healthz` with the status in the returned cell,
/// `/slow` with its name after 800 ms, and anything else with its name.
async fn spawn_backend(name: &'static str) -> (SocketAddr, Arc<AtomicU16>) {
    let health = Arc::new(AtomicU16::new(200));
    let status = Arc::clone(&health);
    let addr = serve_http1(move |req: Request<Incoming>| {
        let status = status.load(Ordering::SeqCst);
        async move {
            match req.uri().path() {
                "/healthz" => Response::builder()
                    .status(status)
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
                path => {
                    if path == "/slow" {
                        tokio::time::sleep(Duration::from_millis(800)).await;
                    }
                    Response::new(Full::new(Bytes::from(name)))
                }
            }
        }
    })
    .await;
    (addr, health)
}

fn health_status(backend: SocketAddr) -> String {
    format!("gfe_backend_health_status{{pool=\"pool\",backend=\"{backend}\"}}")
}

#[tokio::test]
async fn a_backend_failing_its_probe_gets_no_requests_until_it_passes_again() {
    let (a, a_health) = spawn_backend("a").await;
    let (b, _) = spawn_backend("b").await;
    let mut config = forwarding_config(a);
    config.pools[0] = common::pool("pool", Scheme::Http, &[a, b]);
    config.pools[0].health_check = Some(quick_check(ProbeType::Http));
    let node = Node::serving("failing", &config);
    let addr = node.addr("http");
    node.wait_for_metric(&format!("{} 1", health_status(a)))
        .await;

    a_health.store(503, Ordering::SeqCst);
    node.wait_for_metric(&format!("{} 0", health_status(a)))
        .await;
    for _ in 0..6 {
        assert_eq!(http_get(addr, "a.example.org", "/").await.1, "b");
    }

    a_health.store(200, Ordering::SeqCst);
    node.wait_for_metric(&format!("{} 1", health_status(a)))
        .await;
    let mut bodies = Vec::new();
    for _ in 0..6 {
        bodies.push(http_get(addr, "a.example.org", "/").await.1);
    }
    assert!(bodies.iter().any(|body| body == "a"), "{bodies:?}");
}

#[tokio::test]
async fn a_backend_answering_the_drain_status_finishes_its_requests_and_gets_no_new_one() {
    let (a, a_health) = spawn_backend("a").await;
    let mut config = forwarding_config(a);
    config.pools[0].health_check = Some(quick_check(ProbeType::Http));
    let node = Node::serving("draining", &config);
    let addr = node.addr("http");
    node.wait_for_metric(&format!("{} 1", health_status(a)))
        .await;
    let in_flight = tokio::spawn(http_get(addr, "a.example.org", "/slow"));
    node.wait_for_metric(&format!(
        "gfe_upstream_requests_in_flight{{pool=\"pool\",backend=\"{a}\"}} 1"
    ))
    .await;

    a_health.store(418, Ordering::SeqCst);
    node.wait_for_metric(&format!(
        "gfe_backend_draining{{pool=\"pool\",backend=\"{a}\"}} 1"
    ))
    .await;

    assert_eq!(http_get(addr, "a.example.org", "/").await.0, 503);
    assert_eq!(in_flight.await.unwrap(), (200, "a".to_string()));
}

/// The framed `grpc.health.v1.HealthCheckResponse` of serving status
/// `status` (1: SERVING, 2: NOT_SERVING).
fn health_check_response(status: u8) -> Bytes {
    Bytes::from(vec![0, 0, 0, 0, 2, 0x08, status])
}

/// A cleartext HTTP/2 gRPC backend implementing the health service, with
/// the serving status in the returned cell, and answering any other call
/// with its name.
async fn spawn_grpc_backend() -> (SocketAddr, Arc<AtomicU16>) {
    let serving = Arc::new(AtomicU16::new(1));
    let status = Arc::clone(&serving);
    let addr = serve_h2c(move |req: Request<Incoming>| {
        let status = status.load(Ordering::SeqCst) as u8;
        async move {
            let (tx, rx) = tokio::sync::mpsc::channel(2);
            let message = if req.uri().path() == "/grpc.health.v1.Health/Check" {
                health_check_response(status)
            } else {
                Bytes::from_static(b"grpc-backend")
            };
            tx.try_send(Frame::data(message)).unwrap();
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", "0".parse().unwrap());
            tx.try_send(Frame::trailers(trailers)).unwrap();
            Response::builder()
                .header("content-type", "application/grpc")
                .body(ChannelBody(rx))
                .unwrap()
        }
    })
    .await;
    (addr, serving)
}

#[tokio::test]
async fn probes_a_grpc_backend_with_the_grpc_health_service() {
    let (backend, serving) = spawn_grpc_backend().await;
    let mut config = common::grpc_config(backend);
    config.pools[0].id = gfe_config::PoolId("pool".into());
    config.routes[0].action = gfe_config::RouteAction::Forward("pool".into());
    config.pools[0].health_check = Some(quick_check(ProbeType::Grpc));
    let node = Node::serving("grpc-health", &config);

    node.wait_for_metric(&format!("{} 1", health_status(backend)))
        .await;
    // The backend ends every call at once without reading the request, and
    // HTTP/2 then lets the client send no more: the call sends nothing.
    let answer = common::h2_request(
        node.addr("http"),
        "POST",
        "http://grpc.example.org/echo.Echo/Stream",
        "",
    )
    .await;
    assert_eq!(answer.body, "grpc-backend");

    serving.store(2, Ordering::SeqCst);
    node.wait_for_metric(&format!(
        "gfe_backend_draining{{pool=\"pool\",backend=\"{backend}\"}} 1"
    ))
    .await;
}
