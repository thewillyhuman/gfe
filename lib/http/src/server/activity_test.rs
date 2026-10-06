use super::*;
use crate::body::{BodyExt, full};

const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(75);

fn activity(accepted_at: Instant) -> Arc<ConnActivity> {
    ConnActivity::new(accepted_at, HEADER_TIMEOUT, IDLE_TIMEOUT)
}

#[test]
fn waits_for_the_first_request_until_the_header_timeout() {
    let accepted = Instant::now();
    let activity = activity(accepted);

    let verdict = activity.verdict(accepted + Duration::from_secs(9));

    assert_eq!(verdict, Verdict::CheckAgainAt(accepted + HEADER_TIMEOUT));
}

#[test]
fn waits_for_the_first_request_no_longer_than_an_idle_timeout_at_a_time() {
    let accepted = Instant::now();
    let idle_timeout = Duration::from_secs(1);
    let activity = ConnActivity::new(accepted, HEADER_TIMEOUT, idle_timeout);
    let now = accepted + Duration::from_secs(2);

    let verdict = activity.verdict(now);

    assert_eq!(verdict, Verdict::CheckAgainAt(now + idle_timeout));
}

#[test]
fn times_out_a_connection_that_never_sends_a_request() {
    let accepted = Instant::now();
    let activity = activity(accepted);

    let verdict = activity.verdict(accepted + HEADER_TIMEOUT);

    assert_eq!(verdict, Verdict::HeaderTimeout);
}

#[test]
fn never_times_out_while_a_request_is_in_flight() {
    let accepted = Instant::now();
    let activity = activity(accepted);
    let _guard = activity.begin_request();
    let much_later = accepted + Duration::from_secs(3600);

    let verdict = activity.verdict(much_later);

    assert_eq!(verdict, Verdict::CheckAgainAt(much_later + IDLE_TIMEOUT));
}

#[test]
fn times_out_once_idle_for_the_idle_timeout_after_the_last_request() {
    let accepted = Instant::now();
    let activity = activity(accepted);
    drop(activity.begin_request());
    let finished = Instant::now();

    let before = activity.verdict(accepted + Duration::from_secs(74));
    let after = activity.verdict(finished + IDLE_TIMEOUT);

    assert!(matches!(before, Verdict::CheckAgainAt(_)), "{before:?}");
    assert_eq!(after, Verdict::IdleTimeout);
}

#[test]
fn counts_every_request_begun() {
    let activity = activity(Instant::now());

    drop(activity.begin_request());
    let _second = activity.begin_request();

    assert_eq!(activity.requests(), 2);
}

#[test]
fn a_request_is_in_flight_until_its_guard_is_dropped() {
    let activity = activity(Instant::now());
    let guard = activity.begin_request();
    let while_held = activity.has_request_in_flight();

    drop(guard);

    assert!(while_held);
    assert!(!activity.has_request_in_flight());
}

#[tokio::test]
async fn a_response_body_keeps_its_request_in_flight_until_dropped() {
    let activity = activity(Instant::now());
    let body = InFlightBody::new(full("hello"), activity.begin_request());

    let collected = body.collect().await.unwrap().to_bytes();

    assert_eq!(collected, "hello");
    assert!(!activity.has_request_in_flight());
}

#[test]
fn a_response_body_not_yet_sent_keeps_its_request_in_flight() {
    let activity = activity(Instant::now());

    let body = InFlightBody::new(full("hello"), activity.begin_request());

    assert!(activity.has_request_in_flight());
    assert!(!body.is_end_stream());
    assert_eq!(body.size_hint().exact(), Some(5));
}
