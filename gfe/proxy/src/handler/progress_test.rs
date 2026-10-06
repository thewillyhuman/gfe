use super::*;
use netkit_http::body::Frame;
use std::pin::Pin;
use std::task::{Context, Poll};

fn timeouts() -> TimeoutsConfig {
    TimeoutsConfig {
        upstream_first_byte: Duration::from_secs(30),
        request_total: Duration::from_secs(60),
        ..Default::default()
    }
}

fn after(start: Instant, secs: u64) -> Instant {
    start + Duration::from_secs(secs)
}

#[test]
fn bodyless_request_is_due_first_byte_after_the_attempt_starts() {
    let start = Instant::now();
    let progress = SendProgress::begin(start, false);
    progress.attempt_started(start);

    assert_eq!(progress.response_deadline(&timeouts()), after(start, 30));
}

#[test]
fn retries_together_are_bounded_by_request_total() {
    let start = Instant::now();
    let progress = SendProgress::begin(start, false);
    // A second attempt, started 45s in, may not run its full 30s.
    progress.attempt_started(after(start, 45));

    assert_eq!(progress.response_deadline(&timeouts()), after(start, 60));
}

#[test]
fn upload_in_progress_is_only_bounded_by_its_own_progress() {
    let start = Instant::now();
    let progress = SendProgress::begin(start, true);
    progress.attempt_started(start);
    // Ten minutes into the upload, a piece of the body goes out.
    progress.body_progressed(after(start, 600));

    assert!(!progress.request_complete());
    assert_eq!(progress.response_deadline(&timeouts()), after(start, 630));
}

#[test]
fn client_with_nothing_to_send_is_waited_for() {
    let progress = SendProgress::begin(Instant::now(), true);

    progress.body_polled(true);

    assert!(progress.waiting_for_client());
}

#[test]
fn client_is_not_waited_for_once_it_sends_again() {
    let progress = SendProgress::begin(Instant::now(), true);
    progress.body_polled(true);

    progress.body_polled(false);

    assert!(!progress.waiting_for_client());
}

#[test]
fn response_is_due_first_byte_after_the_upload_ends() {
    let start = Instant::now();
    let progress = SendProgress::begin(start, true);
    progress.attempt_started(start);
    progress.body_ended(after(start, 600));

    assert!(progress.request_complete());
    assert_eq!(progress.response_deadline(&timeouts()), after(start, 630));
}

#[tokio::test]
async fn is_overdue_once_the_deadline_has_passed() {
    let short = TimeoutsConfig {
        upstream_first_byte: Duration::from_millis(20),
        ..timeouts()
    };
    let start = Instant::now();
    let progress = SendProgress::begin(start, false);
    progress.attempt_started(start);

    progress.overdue(&short).await;

    assert!(start.elapsed() >= Duration::from_millis(20));
}

/// A body whose client has nothing to give yet.
struct Stalled;

impl Body for Stalled {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Poll::Pending
    }
}

fn poll_once<B: Body<Data = Bytes> + Unpin>(body: &mut CountedBody<B>) {
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let _ = Pin::new(body).poll_frame(&mut cx);
}

#[test]
fn notes_a_client_with_nothing_to_give() {
    let progress = SendProgress::begin(Instant::now(), true);
    let mut body = CountedBody::new(Stalled, Arc::default(), Arc::clone(&progress));

    poll_once(&mut body);

    assert!(progress.waiting_for_client());
}

#[test]
fn does_not_wait_for_a_client_that_gave_a_frame() {
    let progress = SendProgress::begin(Instant::now(), true);
    let chunk = http_body_util::Full::new(Bytes::from_static(b"chunk"));
    let mut body = CountedBody::new(chunk, Arc::default(), Arc::clone(&progress));

    poll_once(&mut body);

    assert!(!progress.waiting_for_client());
}

#[test]
fn counts_the_bytes_sent_and_notes_the_end_of_the_body() {
    let progress = SendProgress::begin(Instant::now(), true);
    let bytes = Arc::new(AtomicU64::new(0));
    let chunk = http_body_util::Full::new(Bytes::from_static(b"chunk"));
    let mut body = CountedBody::new(chunk, Arc::clone(&bytes), Arc::clone(&progress));

    poll_once(&mut body);

    assert_eq!(bytes.load(Ordering::Relaxed), 5);
    assert!(progress.request_complete());
}

#[test]
fn a_body_empty_from_the_start_is_complete_at_once() {
    let progress = SendProgress::begin(Instant::now(), true);

    CountedBody::new(
        http_body_util::Empty::<Bytes>::new(),
        Arc::default(),
        Arc::clone(&progress),
    );

    assert!(progress.request_complete());
}
