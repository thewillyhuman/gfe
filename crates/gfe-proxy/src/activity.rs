//! Per-connection request activity, used to enforce the client-side timeouts.
//!
//! hyper bounds how long it waits for an HTTP/1 request head, but it has no
//! notion of an idle HTTP/2 connection and cannot tell a connection that never
//! sent a request from one waiting between keep-alive requests. This module
//! tracks the one fact needed to decide both: whether a request is in flight,
//! and since when none has been.

use crate::errors::RespBody;
use bytes::Bytes;
use gfe_core::config::TimeoutsConfig;
use gfe_core::upstream::BoxError;
use hyper::body::{Body, Frame, SizeHint};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

/// What the connection watchdog must do, given the activity so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// No request head arrived within `request_header` of accepting the
    /// connection. Nothing is in flight, so the connection is simply closed.
    HeaderTimeout,
    /// No request has been in flight for `client_idle`.
    IdleTimeout,
    /// Within limits; nothing can expire before this instant.
    CheckAgainAt(Instant),
}

/// Request activity on one client connection.
///
/// A request is *in flight* from the moment its head is parsed until its
/// response body has been fully written (or abandoned), which is what
/// [`RequestGuard`] measures.
#[derive(Debug)]
pub struct ConnActivity {
    accepted_at: Instant,
    requests: AtomicU64,
    in_flight: AtomicUsize,
    /// When the connection last became idle, in milliseconds since
    /// `accepted_at`. Only meaningful while `in_flight` is zero.
    idle_since_ms: AtomicU64,
}

impl ConnActivity {
    /// Start tracking a connection accepted at `accepted_at`.
    pub fn new(accepted_at: Instant) -> Arc<Self> {
        Arc::new(ConnActivity {
            accepted_at,
            requests: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
            idle_since_ms: AtomicU64::new(0),
        })
    }

    /// Record the start of a request. The request stays in flight until the
    /// returned guard is dropped.
    pub fn begin_request(self: &Arc<Self>) -> RequestGuard {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        RequestGuard(self.clone())
    }

    /// Requests started on this connection so far.
    pub fn requests(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }

    /// Whether a request is in flight right now.
    pub fn has_request_in_flight(&self) -> bool {
        self.in_flight.load(Ordering::Relaxed) > 0
    }

    /// Decide what the watchdog must do at `now`.
    pub fn verdict(&self, now: Instant, timeouts: &TimeoutsConfig) -> Verdict {
        let deadline = if self.requests() == 0 {
            self.accepted_at + timeouts.request_header
        } else if self.in_flight.load(Ordering::Relaxed) > 0 {
            // Even if the request ended right now, the connection could not
            // be idle for long enough before this.
            return Verdict::CheckAgainAt(now + timeouts.client_idle);
        } else {
            let idle_since = Duration::from_millis(self.idle_since_ms.load(Ordering::Relaxed));
            self.accepted_at + idle_since + timeouts.client_idle
        };

        if now < deadline {
            Verdict::CheckAgainAt(deadline)
        } else if self.requests() == 0 {
            Verdict::HeaderTimeout
        } else {
            Verdict::IdleTimeout
        }
    }
}

/// Keeps a request in flight; dropping it marks the request finished.
#[derive(Debug)]
pub struct RequestGuard(Arc<ConnActivity>);

impl Drop for RequestGuard {
    fn drop(&mut self) {
        let activity = &self.0;
        let idle_since = activity.accepted_at.elapsed().as_millis() as u64;
        // Store before decrementing, so whoever observes zero requests in
        // flight also observes the matching idle start.
        activity.idle_since_ms.store(idle_since, Ordering::Relaxed);
        activity.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A response body that keeps its request in flight until hyper is done with
/// it, i.e. until the last byte is written or the client goes away.
pub struct InFlightBody {
    inner: RespBody,
    _guard: RequestGuard,
}

impl InFlightBody {
    pub fn new(inner: RespBody, guard: RequestGuard) -> Self {
        InFlightBody {
            inner,
            _guard: guard,
        }
    }
}

impl Body for InFlightBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timeouts() -> TimeoutsConfig {
        TimeoutsConfig {
            request_header: Duration::from_secs(10),
            client_idle: Duration::from_secs(75),
            ..Default::default()
        }
    }

    #[test]
    fn waits_for_the_first_request_until_request_header() {
        let accepted = Instant::now();
        let activity = ConnActivity::new(accepted);

        let verdict = activity.verdict(accepted + Duration::from_secs(9), &timeouts());

        assert_eq!(
            verdict,
            Verdict::CheckAgainAt(accepted + Duration::from_secs(10))
        );
    }

    #[test]
    fn times_out_a_connection_that_never_sends_a_request() {
        let accepted = Instant::now();
        let activity = ConnActivity::new(accepted);

        let verdict = activity.verdict(accepted + Duration::from_secs(10), &timeouts());

        assert_eq!(verdict, Verdict::HeaderTimeout);
    }

    #[test]
    fn never_times_out_while_a_request_is_in_flight() {
        let accepted = Instant::now();
        let activity = ConnActivity::new(accepted);
        let _guard = activity.begin_request();
        let much_later = accepted + Duration::from_secs(3600);

        let verdict = activity.verdict(much_later, &timeouts());

        assert_eq!(
            verdict,
            Verdict::CheckAgainAt(much_later + Duration::from_secs(75))
        );
    }

    #[test]
    fn times_out_once_idle_for_client_idle_after_the_last_request() {
        let accepted = Instant::now();
        let activity = ConnActivity::new(accepted);
        drop(activity.begin_request());
        let finished = Instant::now();

        let before = activity.verdict(accepted + Duration::from_secs(74), &timeouts());
        let after = activity.verdict(finished + Duration::from_secs(75), &timeouts());

        assert!(matches!(before, Verdict::CheckAgainAt(_)), "{before:?}");
        assert_eq!(after, Verdict::IdleTimeout);
    }
}
