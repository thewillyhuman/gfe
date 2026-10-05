use super::*;

fn header<'a>(answer: &'a Answer, name: &str) -> &'a str {
    answer.header.headers[name].to_str().unwrap()
}

#[test]
fn synthetic_answer_has_status_text_and_request_id() {
    let answer = synthetic(StatusCode::NOT_FOUND, "no route", "abc123");

    assert_eq!(answer.status(), 404);
    assert_eq!(header(&answer, "x-request-id"), "abc123");
    assert_eq!(header(&answer, "content-type"), "text/plain; charset=utf-8");
    assert_eq!(answer.body, "404 no route\nrequest-id: abc123\n");
    assert_eq!(
        header(&answer, "content-length"),
        answer.body.len().to_string()
    );
}

#[test]
fn gateway_failures_are_unavailable_to_grpc() {
    for status in [502, 503, 504] {
        let status = StatusCode::from_u16(status).unwrap();
        assert_eq!(GrpcCode::for_http_status(status), GrpcCode::Unavailable);
    }
}

#[test]
fn unrouted_calls_are_unimplemented_to_grpc() {
    assert_eq!(
        GrpcCode::for_http_status(StatusCode::NOT_FOUND),
        GrpcCode::Unimplemented
    );
}

#[test]
fn grpc_failure_is_a_trailers_only_response() {
    let answer = grpc_failure(GrpcCode::Unavailable, "gfe: no_healthy_upstream", "abc123");

    assert_eq!(answer.status(), 200);
    assert_eq!(header(&answer, "content-type"), "application/grpc");
    assert_eq!(header(&answer, "grpc-status"), "14");
    assert_eq!(header(&answer, "grpc-message"), "gfe: no_healthy_upstream");
    assert_eq!(header(&answer, "x-request-id"), "abc123");
    assert!(answer.body.is_empty());
    assert_eq!(answer.grpc_status(), Some(14));
}

#[test]
fn refusal_of_a_grpc_call_is_a_grpc_failure_with_the_reason() {
    let answer = refusal(Refusal::NoRoute, "abc123", true);

    assert_eq!(answer.status(), 200);
    assert_eq!(header(&answer, "grpc-status"), "12");
    assert_eq!(header(&answer, "grpc-message"), "gfe: no_route");
}

#[test]
fn refusal_of_a_plain_request_is_a_synthetic_answer() {
    let answer = refusal(Refusal::NoHealthyUpstream, "abc123", false);

    assert_eq!(answer.status(), 503);
    assert_eq!(answer.body, "503 no healthy upstream\nrequest-id: abc123\n");
    assert_eq!(answer.grpc_status(), None);
}

#[test]
fn refusals_keep_the_old_statuses_and_reasons() {
    let cases = [
        (Refusal::HostConflict, 400, "host_conflict"),
        (Refusal::HostMissing, 400, "host_missing"),
        (Refusal::Misdirected, 421, "misdirected_request"),
        (Refusal::HeaderTooLarge, 431, "request_header_too_large"),
        (Refusal::NoRoute, 404, "no_route"),
        (
            Refusal::UnsupportedTarget,
            400,
            "unsupported_request_target",
        ),
        (Refusal::UpgradeNotSupported, 501, "upgrade_not_supported"),
        (Refusal::PoolNotFound, 502, "pool_not_found"),
        (Refusal::PoolFull, 503, "upstream_pool_full"),
        (Refusal::NoHealthyUpstream, 503, "no_healthy_upstream"),
        (Refusal::RequestBodyTimeout, 408, "request_body_timeout"),
        (
            Refusal::Upstream(FailureKind::ConnectRefused),
            502,
            "upstream_connect_refused",
        ),
        (
            Refusal::Upstream(FailureKind::ConnectTimeout),
            502,
            "upstream_connect_timeout",
        ),
        (
            Refusal::Upstream(FailureKind::ConnectionLimit),
            503,
            "upstream_connection_limit",
        ),
        (
            Refusal::Upstream(FailureKind::Timeout),
            504,
            "upstream_timeout",
        ),
    ];
    for (refusal, status, reason) in cases {
        assert_eq!(refusal.status().as_u16(), status, "{refusal:?}");
        assert_eq!(refusal.reason(), reason, "{refusal:?}");
    }
}

#[test]
fn redirect_names_the_same_host_and_path_under_the_scheme() {
    let answer = redirect("https", 308, "a.example.org", "/path?q=1", "abc123");

    assert_eq!(answer.status(), 308);
    assert_eq!(
        header(&answer, "location"),
        "https://a.example.org/path?q=1"
    );
    assert_eq!(header(&answer, "x-request-id"), "abc123");
    assert!(answer.body.is_empty());
}

#[test]
fn redirect_with_an_invalid_status_is_permanent() {
    assert_eq!(redirect("https", 1000, "a", "/", "id").status(), 308);
}

#[test]
fn fixed_answer_has_the_configured_status_and_body() {
    let answer = fixed(200, "ok", "abc123");

    assert_eq!(answer.status(), 200);
    assert_eq!(answer.body, "ok");
    assert_eq!(header(&answer, "content-length"), "2");
    assert_eq!(header(&answer, "x-request-id"), "abc123");
}
