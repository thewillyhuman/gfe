use super::*;
use crate::mock_backend;
use std::time::Instant;

const TIMEOUT: Duration = Duration::from_secs(2);

fn http_check(drain_status: Option<u16>) -> HealthCheckConfig {
    HealthCheckConfig {
        probe_type: ProbeType::Http,
        drain_status,
        ..HealthCheckConfig::default()
    }
}

fn probe_type(probe_type: ProbeType) -> HealthCheckConfig {
    HealthCheckConfig {
        probe_type,
        ..HealthCheckConfig::default()
    }
}

// TCP

#[tokio::test]
async fn tcp_probe_detects_closed_port() {
    let port = mock_backend::closed_port().await;
    assert_eq!(
        TcpProbe.check("127.0.0.1", port, TIMEOUT).await,
        ProbeResult::Fail
    );
}

#[tokio::test]
async fn tcp_probe_detects_open_port() {
    let port = mock_backend::silent().await;
    assert_eq!(
        TcpProbe.check("127.0.0.1", port, TIMEOUT).await,
        ProbeResult::Pass
    );
}

// HTTP

#[tokio::test]
async fn http_probe_passes_the_expected_status() {
    let backend = mock_backend::http(200).await;
    let probe = make_probe(&http_check(None), Scheme::Http);
    assert_eq!(
        probe.check("127.0.0.1", backend.port, TIMEOUT).await,
        ProbeResult::Pass
    );
}

#[tokio::test]
async fn http_probe_fails_another_status() {
    let backend = mock_backend::http(500).await;
    let probe = make_probe(&http_check(Some(503)), Scheme::Http);
    assert_eq!(
        probe.check("127.0.0.1", backend.port, TIMEOUT).await,
        ProbeResult::Fail
    );
}

#[tokio::test]
async fn http_probe_drains_on_the_drain_status() {
    let backend = mock_backend::http(503).await;
    let probe = make_probe(&http_check(Some(503)), Scheme::Http);
    assert_eq!(
        probe.check("127.0.0.1", backend.port, TIMEOUT).await,
        ProbeResult::Drain
    );
}

#[tokio::test]
async fn http_probe_fails_a_refused_connection() {
    let port = mock_backend::closed_port().await;
    let probe = make_probe(&http_check(None), Scheme::Http);
    assert_eq!(
        probe.check("127.0.0.1", port, TIMEOUT).await,
        ProbeResult::Fail
    );
}

/// The configured timeout bounds the whole probe, whatever Pingora's own
/// timeouts are.
#[tokio::test]
async fn http_probe_fails_a_silent_backend_within_the_timeout() {
    let port = mock_backend::silent().await;
    let probe = make_probe(&http_check(None), Scheme::Http);
    let timeout = Duration::from_millis(200);

    let start = Instant::now();
    let result = probe.check("127.0.0.1", port, timeout).await;

    assert_eq!(result, ProbeResult::Fail);
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "{:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn https_probe_fails_a_silent_backend_within_the_timeout() {
    let port = mock_backend::silent().await;
    let probe = make_probe(&probe_type(ProbeType::Https), Scheme::Http);
    let timeout = Duration::from_millis(200);

    let start = Instant::now();
    let result = probe.check("127.0.0.1", port, timeout).await;

    assert_eq!(result, ProbeResult::Fail);
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "{:?}",
        start.elapsed()
    );
}

/// The probe connects to the first address the name resolves to, where
/// the backend listens.
#[tokio::test]
async fn http_probe_reaches_a_backend_given_by_name() {
    let backend = mock_backend::http_at("localhost", 200).await;
    let probe = make_probe(&http_check(None), Scheme::Http);
    assert_eq!(
        probe.check("localhost", backend.port, TIMEOUT).await,
        ProbeResult::Pass
    );
}

#[tokio::test]
async fn http_probe_fails_a_name_that_does_not_resolve() {
    let probe = make_probe(&http_check(None), Scheme::Http);
    assert_eq!(
        probe.check("does-not-exist.invalid", 80, TIMEOUT).await,
        ProbeResult::Fail
    );
}

/// The node default probe type is `http`: a pool of scheme `https`
/// inheriting it must be probed the way its traffic reaches it.
#[tokio::test]
async fn http_probe_uses_tls_for_an_https_pool() {
    let backend = mock_backend::https(200).await;
    let probe = make_probe(&HealthCheckConfig::default(), Scheme::Https);
    assert_eq!(
        probe.check("127.0.0.1", backend.port, TIMEOUT).await,
        ProbeResult::Pass
    );
}

#[tokio::test]
async fn http_probe_stays_cleartext_for_an_http_pool() {
    let backend = mock_backend::https(200).await;
    let probe = make_probe(&HealthCheckConfig::default(), Scheme::Http);
    assert_eq!(
        probe.check("127.0.0.1", backend.port, TIMEOUT).await,
        ProbeResult::Fail
    );
}

/// The certificate is self-signed for `localhost`, and the probe sends
/// `localhost` as SNI: it is accepted all the same, since probes do not
/// verify certificates.
#[tokio::test]
async fn https_probe_accepts_a_self_signed_certificate() {
    let backend = mock_backend::https_at("localhost", 200).await;
    let probe = make_probe(&probe_type(ProbeType::Https), Scheme::Http);
    assert_eq!(
        probe.check("localhost", backend.port, TIMEOUT).await,
        ProbeResult::Pass
    );
}

#[tokio::test]
async fn https_probe_drains_on_the_drain_status() {
    let backend = mock_backend::https(503).await;
    let check = HealthCheckConfig {
        drain_status: Some(503),
        ..probe_type(ProbeType::Https)
    };
    let probe = make_probe(&check, Scheme::Http);
    assert_eq!(
        probe.check("127.0.0.1", backend.port, TIMEOUT).await,
        ProbeResult::Drain
    );
}

// gRPC

#[test]
fn the_check_request_asks_about_the_whole_server() {
    // One uncompressed frame of length 0: an empty `HealthCheckRequest`,
    // whose `service` is "".
    assert_eq!(CHECK_REQUEST, &[0, 0, 0, 0, 0]);
}

#[test]
fn reads_the_serving_status_from_a_check_response() {
    assert_eq!(
        serving_status(&[0, 0, 0, 0, 2, 0x08, 1]),
        Some(ServingStatus::Serving)
    );
    assert_eq!(
        serving_status(&[0, 0, 0, 0, 2, 0x08, 2]),
        Some(ServingStatus::NotServing)
    );
}

#[test]
fn an_empty_check_response_is_not_serving_status() {
    // An empty message is the protobuf default: UNKNOWN.
    assert_eq!(serving_status(&[0, 0, 0, 0, 0]), Some(ServingStatus::Other));
}

#[test]
fn a_truncated_check_response_has_no_status() {
    assert_eq!(serving_status(&[]), None);
    assert_eq!(serving_status(&[0, 0, 0, 0, 2, 0x08]), None);
}

#[test]
fn a_compressed_check_response_has_no_status() {
    assert_eq!(serving_status(&[1, 0, 0, 0, 2, 0x08, 1]), None);
}

#[test]
fn an_ipv6_backend_is_bracketed_in_the_authority() {
    assert_eq!(authority("2001:db8::1", 50051), "[2001:db8::1]:50051");
    assert_eq!(authority("backend.example", 50051), "backend.example:50051");
}

async fn grpc_check(port: u16, scheme: Scheme) -> ProbeResult {
    make_probe(&probe_type(ProbeType::Grpc), scheme)
        .check("127.0.0.1", port, TIMEOUT)
        .await
}

#[tokio::test]
async fn grpc_probe_passes_a_serving_backend() {
    let port = mock_backend::grpc_health(Some(1), false).await;
    assert_eq!(grpc_check(port, Scheme::H2c).await, ProbeResult::Pass);
}

#[tokio::test]
async fn grpc_probe_drains_a_backend_that_is_not_serving() {
    let port = mock_backend::grpc_health(Some(2), false).await;
    assert_eq!(grpc_check(port, Scheme::H2c).await, ProbeResult::Drain);
}

#[tokio::test]
async fn grpc_probe_fails_a_backend_with_an_unknown_status() {
    let port = mock_backend::grpc_health(Some(0), false).await;
    assert_eq!(grpc_check(port, Scheme::H2c).await, ProbeResult::Fail);
}

#[tokio::test]
async fn grpc_probe_fails_a_backend_without_a_health_service() {
    let port = mock_backend::grpc_health(None, false).await;
    assert_eq!(grpc_check(port, Scheme::H2c).await, ProbeResult::Fail);
}

#[tokio::test]
async fn grpc_probe_fails_a_backend_that_is_down() {
    let port = mock_backend::closed_port().await;
    assert_eq!(grpc_check(port, Scheme::H2c).await, ProbeResult::Fail);
}

#[tokio::test]
async fn grpc_probe_passes_a_serving_backend_over_tls() {
    let port = mock_backend::grpc_health(Some(1), true).await;
    assert_eq!(grpc_check(port, Scheme::Https).await, ProbeResult::Pass);
}

#[tokio::test]
async fn grpc_probe_drains_a_backend_that_is_not_serving_over_tls() {
    let port = mock_backend::grpc_health(Some(2), true).await;
    assert_eq!(grpc_check(port, Scheme::Https).await, ProbeResult::Drain);
}

#[tokio::test]
async fn grpc_probe_fails_a_backend_without_a_health_service_over_tls() {
    let port = mock_backend::grpc_health(None, true).await;
    assert_eq!(grpc_check(port, Scheme::Https).await, ProbeResult::Fail);
}

#[tokio::test]
async fn grpc_probe_fails_a_silent_backend_within_the_timeout() {
    let port = mock_backend::silent().await;
    let probe = make_probe(&probe_type(ProbeType::Grpc), Scheme::H2c);
    let timeout = Duration::from_millis(200);

    let start = Instant::now();
    let result = probe.check("127.0.0.1", port, timeout).await;

    assert_eq!(result, ProbeResult::Fail);
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "{:?}",
        start.elapsed()
    );
}
