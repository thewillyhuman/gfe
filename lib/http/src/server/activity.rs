//! Request activity on one connection, the one fact the connection timers
//! are decided on.
//!
//! hyper bounds how long it waits for an HTTP/1 request head, but it has no
//! notion of an idle HTTP/2 connection and cannot tell a connection that
//! never sent a request from one waiting between keep-alive requests. This
//! module tracks whether a request is in flight, and since when none has
//! been, and says what is due. It does no I/O and keeps no timer: acting on
//! a [`Verdict`] is the caller's business.
//!
//! Time is tokio's, so that tests running on paused time see it pass.

use crate::body::{Body, BoxBody, BoxError, Frame, SizeHint};
use bytes::Bytes;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::Instant;

/// What is due on a connection, given its activity so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Verdict {
    /// No request head arrived within the header timeout of serving
    /// beginning. Nothing is in flight, so the connection can simply be
    /// closed.
    HeaderTimeout,
    /// No request has been in flight for the idle timeout.
    IdleTimeout,
    /// Within limits; nothing can expire before this instant.
    CheckAgainAt(Instant),
}

/// Request activity on one connection.
///
/// A request is *in flight* from the moment its head is parsed until its
/// response body has been sent to the end or dropped, which is how long its
/// [`RequestGuard`] lives.
#[derive(Debug)]
pub(super) struct ConnActivity {
    accepted_at: Instant,
    header_timeout: Duration,
    idle_timeout: Duration,
    requests: AtomicU64,
    in_flight: AtomicUsize,
    /// When the connection last became idle, in milliseconds since
    /// `accepted_at`. Only meaningful while `in_flight` is zero.
    idle_since_ms: AtomicU64,
}

impl ConnActivity {
    /// Start tracking a connection served since `accepted_at`, whose first
    /// request head is due within `header_timeout` and which may go
    /// `idle_timeout` without a request in flight.
    pub(super) fn new(
        accepted_at: Instant,
        header_timeout: Duration,
        idle_timeout: Duration,
    ) -> Arc<Self> {
        Arc::new(ConnActivity {
            accepted_at,
            header_timeout,
            idle_timeout,
            requests: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
            idle_since_ms: AtomicU64::new(0),
        })
    }

    /// Record the start of a request. The request stays in flight until the
    /// returned guard is dropped.
    pub(super) fn begin_request(self: &Arc<Self>) -> RequestGuard {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        RequestGuard(self.clone())
    }

    /// Requests begun on this connection so far.
    pub(super) fn requests(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }

    /// Whether a request is in flight right now.
    pub(super) fn has_request_in_flight(&self) -> bool {
        self.in_flight.load(Ordering::Relaxed) > 0
    }

    /// What is due at `now`.
    pub(super) fn verdict(&self, now: Instant) -> Verdict {
        let deadline = if self.requests() == 0 {
            self.accepted_at + self.header_timeout
        } else if self.has_request_in_flight() {
            // Even if the request ended right now, the connection could not
            // be idle for long enough before this.
            return Verdict::CheckAgainAt(now + self.idle_timeout);
        } else {
            let idle_since = Duration::from_millis(self.idle_since_ms.load(Ordering::Relaxed));
            self.accepted_at + idle_since + self.idle_timeout
        };

        if now < deadline && self.requests() == 0 {
            // The first request may arrive and end before the header
            // deadline, and the connection then be idle for longer than
            // the idle timeout before it: look again within one.
            Verdict::CheckAgainAt(deadline.min(now + self.idle_timeout))
        } else if now < deadline {
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
pub(super) struct RequestGuard(Arc<ConnActivity>);

impl Drop for RequestGuard {
    fn drop(&mut self) {
        let activity = &self.0;
        // Saturates after some 584 million years of serving.
        let idle_since =
            u64::try_from(activity.accepted_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        // Store before decrementing, so whoever observes no request in
        // flight also observes the matching idle start.
        activity.idle_since_ms.store(idle_since, Ordering::Relaxed);
        activity.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A response body that keeps its request in flight until hyper is done with
/// it: until the last frame is sent or the client goes away.
pub(super) struct InFlightBody {
    inner: BoxBody,
    _guard: RequestGuard,
}

impl InFlightBody {
    /// `inner`, keeping the request `guard` stands for in flight as long as
    /// it lives.
    pub(super) fn new(inner: BoxBody, guard: RequestGuard) -> Self {
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
#[path = "activity_test.rs"]
mod tests;
