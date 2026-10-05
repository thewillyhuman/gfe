use super::*;

fn upstream(etype: ErrorType) -> Box<Error> {
    Error::new_up(etype)
}

#[test]
fn timeout_while_connecting_is_a_connect_timeout() {
    let failure = classify(&upstream(ErrorType::ConnectTimedout), true, true);

    assert_eq!(failure, Failure::Upstream(FailureKind::ConnectTimeout));
}

#[test]
fn refused_connection_is_connect_refused() {
    let failure = classify(&upstream(ErrorType::ConnectRefused), true, true);

    assert_eq!(failure, Failure::Upstream(FailureKind::ConnectRefused));
}

#[test]
fn failed_tls_handshake_is_tls() {
    for etype in [ErrorType::TLSHandshakeFailure, ErrorType::InvalidCert] {
        let failure = classify(&upstream(etype), true, true);

        assert_eq!(failure, Failure::Upstream(FailureKind::Tls));
    }
}

#[test]
fn refusal_at_the_connection_limit_is_connection_limit() {
    let failure = classify(&upstream(CONNECTION_LIMIT), true, true);

    assert_eq!(failure, Failure::Upstream(FailureKind::ConnectionLimit));
}

#[test]
fn unrecognised_connect_failure_is_a_connect_error() {
    let failure = classify(&upstream(ErrorType::ConnectNoRoute), true, true);

    assert_eq!(failure, Failure::Upstream(FailureKind::ConnectError));
}

#[test]
fn closed_established_connection_is_a_reset() {
    let failure = classify(&upstream(ErrorType::ConnectionClosed), false, true);

    assert_eq!(failure, Failure::Upstream(FailureKind::Reset));
}

#[test]
fn backend_silent_after_the_whole_request_timed_out() {
    let failure = classify(&upstream(ErrorType::ReadTimedout), false, true);

    assert_eq!(failure, Failure::Upstream(FailureKind::Timeout));
}

#[test]
fn backend_that_stops_taking_the_body_timed_out() {
    let failure = classify(&upstream(ErrorType::WriteTimedout), false, false);

    assert_eq!(failure, Failure::Upstream(FailureKind::Timeout));
}

#[test]
fn backend_waiting_for_the_rest_of_the_body_is_a_stalled_client() {
    let failure = classify(&upstream(ErrorType::ReadTimedout), false, false);

    assert_eq!(failure, Failure::ClientStalled);
}

#[test]
fn client_read_timeout_is_a_stalled_client() {
    let failure = classify(&Error::new_down(ErrorType::ReadTimedout), false, false);

    assert_eq!(failure, Failure::ClientStalled);
}

#[test]
fn client_that_closed_is_gone() {
    let failure = classify(&Error::new_down(ErrorType::ConnectionClosed), false, true);

    assert_eq!(failure, Failure::ClientGone);
}

#[test]
fn unrecognised_failure_on_an_established_connection_is_other() {
    let failure = classify(&upstream(ErrorType::InvalidHTTPHeader), false, true);

    assert_eq!(failure, Failure::Upstream(FailureKind::Other));
}

#[test]
fn neither_the_connection_limit_nor_a_timeout_is_retryable() {
    assert!(!FailureKind::ConnectionLimit.is_retryable());
    assert!(!FailureKind::Timeout.is_retryable());
    assert!(FailureKind::ConnectRefused.is_retryable());
}

#[test]
fn the_connection_limit_is_not_the_backends_failure() {
    assert!(!FailureKind::ConnectionLimit.is_the_backends());
    assert!(FailureKind::Reset.is_the_backends());
}

#[test]
fn kinds_keep_their_metric_labels_and_log_reasons() {
    assert_eq!(FailureKind::ConnectRefused.as_str(), "connect_refused");
    assert_eq!(FailureKind::Timeout.as_str(), "timeout");
    assert_eq!(FailureKind::Tls.reason(), "upstream_tls");
    assert_eq!(FailureKind::Other.reason(), "upstream_error");
    assert_eq!(FailureKind::Timeout.reason(), "upstream_timeout");
}
