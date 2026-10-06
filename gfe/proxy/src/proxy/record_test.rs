use super::*;
use crate::metrics::GfeMetrics;
use gfe_config::{RouteAction, RouteId};

fn headers(grpc_status: &'static str) -> HeaderMap {
    let mut map = HeaderMap::new();
    map.insert("grpc-status", http::HeaderValue::from_static(grpc_status));
    map
}

#[test]
fn reads_a_defined_grpc_status() {
    assert_eq!(grpc_status(&headers("0")), Some(0));
    assert_eq!(grpc_status(&headers("14")), Some(14));
}

#[test]
fn ignores_missing_or_undefined_grpc_status() {
    assert_eq!(grpc_status(&HeaderMap::new()), None);
    assert_eq!(grpc_status(&headers("17")), None);
    assert_eq!(grpc_status(&headers("ok")), None);
}

#[test]
fn an_exchange_without_error_is_complete() {
    assert_eq!(Termination::of(None, false, true), Termination::Complete);
}

#[test]
fn an_exchange_gfe_answered_itself_is_complete() {
    assert_eq!(
        Termination::of(Some(Side::Upstream), true, true),
        Termination::Complete
    );
}

#[test]
fn an_exchange_the_client_broke_off_is_a_client_abort() {
    assert_eq!(
        Termination::of(Some(Side::Client), false, true),
        Termination::ClientAbort
    );
    assert_eq!(
        Termination::of(Some(Side::Client), false, false),
        Termination::ClientAbort
    );
}

#[test]
fn a_response_the_backend_broke_off_is_an_upstream_abort() {
    assert_eq!(
        Termination::of(Some(Side::Upstream), false, true),
        Termination::UpstreamAbort
    );
}

#[test]
fn a_failure_nobody_could_be_told_of_is_a_client_abort() {
    assert_eq!(
        Termination::of(Some(Side::Upstream), false, false),
        Termination::ClientAbort
    );
}

#[test]
fn keeps_millisecond_values_to_the_microsecond() {
    assert_eq!(millis(Duration::from_micros(1500)), 1.5);
}

fn record() -> RequestRecord {
    RequestRecord::begin(
        Instant::now(),
        Arrival {
            client: Some("127.0.0.1:5000".parse().unwrap()),
            listener: "http".to_string(),
            is_tls: false,
            sni: None,
            tls_version: None,
            tls_cipher: None,
        },
        "abc".to_string(),
        Method::GET,
        Version::HTTP_11,
        "/".to_string(),
        None,
        false,
    )
}

#[test]
fn reports_a_request_without_a_response_as_499_by_the_client() {
    let metrics = GfeMetrics::new();
    metrics.proxy.requests_in_flight.inc();

    record().report(&metrics.proxy);

    let exposed = metrics.encode();
    assert!(
        exposed.contains(
            r#"gfe_requests_total{listener="http",vhost="none",route="none",status="499"} 1"#
        ),
        "{exposed}"
    );
    assert!(
        exposed.contains(
            r#"gfe_requests_aborted_total{listener="http",vhost="none",route="none",by="client"} 1"#
        ),
        "{exposed}"
    );
    assert!(exposed.contains("gfe_requests_in_flight 0"), "{exposed}");
}

#[test]
fn reports_a_routed_request_under_its_route_and_host_pattern() {
    let metrics = GfeMetrics::new();
    metrics.proxy.requests_in_flight.inc();
    let mut record = record();
    record.route = Some(Arc::new(CompiledRoute {
        id: RouteId("web".into()),
        host: "*.example.org".into(),
        path_prefix: "/".into(),
        action: RouteAction::Forward("pool".into()),
    }));
    record.status = Some(200);
    record.termination = Termination::Complete;
    record.request_bytes = 3;
    record.response_bytes = 5;
    record.grpc_status = Some(0);

    record.report(&metrics.proxy);

    let exposed = metrics.encode();
    let labels = r#"listener="http",vhost="*.example.org",route="web""#;
    for expected in [
        format!("gfe_requests_total{{{labels},status=\"200\"}} 1"),
        format!("gfe_request_body_bytes_total{{{labels}}} 3"),
        format!("gfe_response_body_bytes_total{{{labels}}} 5"),
        format!("gfe_grpc_responses_total{{{labels},grpc_status=\"0\"}} 1"),
    ] {
        assert!(
            exposed.contains(&expected),
            "missing {expected} in {exposed}"
        );
    }
    assert!(
        !exposed.contains("gfe_requests_aborted_total{"),
        "{exposed}"
    );
}
