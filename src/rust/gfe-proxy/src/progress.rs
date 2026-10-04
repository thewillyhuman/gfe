//! How far a request has got on its way to a backend, and from that, when
//! the backend is overdue with its response.
//!
//! Two timeouts bound the wait for response headers:
//!
//! * `upstream_first_byte` — per attempt: the backend must start responding
//!   within this long of having last been sent something, be it the request
//!   itself or a piece of its body. An upload therefore never times out while
//!   it makes progress, and a backend is not blamed for a slow client.
//! * `request_total` — across attempts: once the request has been sent in
//!   full, a response must arrive within this long, however many backends are
//!   tried.
//!
//! When the wait runs out, who is to blame depends on who holds the request
//! up: the client, if GFE last asked it for more of the body and it had none
//! to give; otherwise the backend, which includes one that stopped taking
//! the body, since GFE only asks the client for more once the backend has
//! taken what came before.

use gfe_core::config::TimeoutsConfig;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// `completed_ms` while the request body is still being sent.
const NOT_COMPLETED: u64 = u64::MAX;

/// The sending side of one forwarded request.
#[derive(Debug)]
pub struct SendProgress {
    started: Instant,
    /// When the backend was last sent something, in ms since `started`.
    last_sent_ms: AtomicU64,
    /// When the request was complete, in ms since `started`.
    completed_ms: AtomicU64,
    /// Whether the client had nothing to give when last asked for more of
    /// the request body.
    waiting_for_client: AtomicBool,
}

impl SendProgress {
    /// Start tracking a request being forwarded from `now` on. A request
    /// without a body is complete from the start.
    pub fn begin(now: Instant, has_body: bool) -> Arc<Self> {
        Arc::new(SendProgress {
            started: now,
            last_sent_ms: AtomicU64::new(0),
            completed_ms: AtomicU64::new(if has_body { NOT_COMPLETED } else { 0 }),
            waiting_for_client: AtomicBool::new(false),
        })
    }

    fn elapsed_ms(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.started).as_millis() as u64
    }

    /// An attempt against a backend starts at `now`.
    pub fn attempt_started(&self, now: Instant) {
        self.last_sent_ms
            .store(self.elapsed_ms(now), Ordering::Relaxed);
    }

    /// A piece of the request body was forwarded at `now`.
    pub fn body_progressed(&self, now: Instant) {
        self.last_sent_ms
            .store(self.elapsed_ms(now), Ordering::Relaxed);
    }

    /// The request body ended at `now`: the request has been sent in full.
    pub fn body_ended(&self, now: Instant) {
        let now_ms = self.elapsed_ms(now);
        self.last_sent_ms.store(now_ms, Ordering::Relaxed);
        self.completed_ms.store(now_ms, Ordering::Relaxed);
    }

    /// The client was asked for more of the request body; `pending` says
    /// whether it had nothing to give yet.
    pub fn body_polled(&self, pending: bool) {
        self.waiting_for_client.store(pending, Ordering::Relaxed);
    }

    /// Whether the client is what holds the request up: it had nothing to
    /// give when last asked for more of the request body.
    pub fn waiting_for_client(&self) -> bool {
        self.waiting_for_client.load(Ordering::Relaxed)
    }

    /// Whether the request has been sent in full.
    pub fn request_complete(&self) -> bool {
        self.completed_ms.load(Ordering::Relaxed) != NOT_COMPLETED
    }

    /// The instant by which the response headers must have arrived.
    pub fn response_deadline(&self, timeouts: &TimeoutsConfig) -> Instant {
        let since_start = |ms: u64| self.started + Duration::from_millis(ms);
        let first_byte =
            since_start(self.last_sent_ms.load(Ordering::Relaxed)) + timeouts.upstream_first_byte;
        match self.completed_ms.load(Ordering::Relaxed) {
            NOT_COMPLETED => first_byte,
            completed => first_byte.min(since_start(completed) + timeouts.request_total),
        }
    }

    /// Resolves once the backend is overdue. Sending more of the request
    /// while this is pending moves the deadline, which is re-read on wake.
    pub async fn overdue(&self, timeouts: &TimeoutsConfig) {
        loop {
            let deadline = self.response_deadline(timeouts);
            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline.into()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
