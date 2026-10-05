use super::*;

fn first_failed(failure: FailureKind) -> Attempted {
    Attempted {
        replayable: true,
        attempts: 1,
        response_started: false,
        failure,
    }
}

#[test]
fn retries_a_replayable_request_once_after_a_refused_connection() {
    assert!(may_retry(first_failed(FailureKind::ConnectRefused)));
}

#[test]
fn retries_a_replayable_request_after_a_reset() {
    assert!(may_retry(first_failed(FailureKind::Reset)));
}

#[test]
fn does_not_retry_a_second_time() {
    let second = Attempted {
        attempts: 2,
        ..first_failed(FailureKind::ConnectRefused)
    };

    assert!(!may_retry(second));
}

#[test]
fn does_not_retry_a_request_that_cannot_be_replayed() {
    let post = Attempted {
        replayable: false,
        ..first_failed(FailureKind::ConnectRefused)
    };

    assert!(!may_retry(post));
}

#[test]
fn does_not_retry_once_the_response_has_started() {
    let started = Attempted {
        response_started: true,
        ..first_failed(FailureKind::Reset)
    };

    assert!(!may_retry(started));
}

#[test]
fn does_not_retry_at_the_connection_limit() {
    assert!(!may_retry(first_failed(FailureKind::ConnectionLimit)));
}

#[test]
fn does_not_retry_a_timeout() {
    assert!(!may_retry(first_failed(FailureKind::Timeout)));
}

#[test]
fn idempotent_bodyless_requests_are_replayable() {
    for method in [
        Method::GET,
        Method::HEAD,
        Method::OPTIONS,
        Method::TRACE,
        Method::DELETE,
    ] {
        assert!(is_replayable(&method, false), "{method}");
    }
}

#[test]
fn a_post_is_not_replayable() {
    assert!(!is_replayable(&Method::POST, false));
    assert!(!is_replayable(&Method::PUT, false));
}

#[test]
fn a_request_with_a_body_is_not_replayable() {
    assert!(!is_replayable(&Method::GET, true));
    assert!(!is_replayable(&Method::DELETE, true));
}
