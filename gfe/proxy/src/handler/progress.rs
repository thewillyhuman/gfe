//! How far a request has got on its way to a backend, and from that, when
//! the backend is overdue with its response.
//!
//! Two timeouts bound the wait for the response head:
//!
//! - `upstream_first_byte`, per attempt: the backend must start responding
//!   within this long of having last been sent something, be it the request
//!   itself or a piece of its body. An upload therefore never times out
//!   while it makes progress, whatever the protocol to the backend, and a
//!   backend is not blamed for a slow client.
//! - `request_total`, across attempts: once the request has been sent in
//!   full, a response must arrive within this long of that moment, however
//!   many backends are tried.
//!
//! When the wait runs out, who is to blame depends on who holds the request
//! up: the client, if GFE last asked it for more of the body and it had none
//! to give; otherwise the backend, which includes one that stopped taking
//! the body, since GFE only asks the client for more once the backend has
//! taken what came before.
//!
//! A response that has started is not bounded by either: what happens once
//! the head has arrived is relayed for as long as it takes. gRPC calls are
//! not bounded at all; that is the caller's decision, not this module's.

use gfe_config::TimeoutsConfig;
use netkit_http::Bytes;
use netkit_http::body::{Body, Frame, SizeHint};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

/// `completed_ms` while the request body is still being sent.
const NOT_COMPLETED: u64 = u64::MAX;

/// The sending side of one forwarded request, shared by the request body
/// (which notes its progress) and whoever waits for the response.
#[derive(Debug)]
pub(crate) struct SendProgress {
    started: Instant,
    /// When the backend was last sent something, in ms since `started`.
    last_sent_ms: AtomicU64,
    /// When the request was complete, in ms since `started`.
    completed_ms: AtomicU64,
    /// Whether the client had nothing to give when last asked for more of
    /// the request body.
    waiting_for_client: AtomicBool,
    /// Whether the request body failed: the client went away in the middle
    /// of it, or sent what is not a body.
    client_failed: AtomicBool,
}

impl SendProgress {
    /// Start tracking a request being forwarded from `now` on. A request
    /// without a body (`has_body` false) is complete from the start.
    pub(crate) fn begin(now: Instant, has_body: bool) -> Arc<Self> {
        Arc::new(SendProgress {
            started: now,
            last_sent_ms: AtomicU64::new(0),
            completed_ms: AtomicU64::new(if has_body { NOT_COMPLETED } else { 0 }),
            waiting_for_client: AtomicBool::new(false),
            client_failed: AtomicBool::new(false),
        })
    }

    fn elapsed_ms(&self, now: Instant) -> u64 {
        u64::try_from(now.saturating_duration_since(self.started).as_millis()).unwrap_or(u64::MAX)
    }

    /// An attempt against a backend starts at `now`.
    pub(crate) fn attempt_started(&self, now: Instant) {
        self.last_sent_ms
            .store(self.elapsed_ms(now), Ordering::Relaxed);
    }

    /// A piece of the request body was forwarded at `now`.
    pub(crate) fn body_progressed(&self, now: Instant) {
        self.last_sent_ms
            .store(self.elapsed_ms(now), Ordering::Relaxed);
    }

    /// The request body ended at `now`: the request has been sent in full.
    pub(crate) fn body_ended(&self, now: Instant) {
        let now_ms = self.elapsed_ms(now);
        self.last_sent_ms.store(now_ms, Ordering::Relaxed);
        self.completed_ms.store(now_ms, Ordering::Relaxed);
    }

    /// The client was asked for more of the request body; `pending` says
    /// whether it had nothing to give yet.
    pub(crate) fn body_polled(&self, pending: bool) {
        self.waiting_for_client.store(pending, Ordering::Relaxed);
    }

    /// Whether the client is what holds the request up: it had nothing to
    /// give when last asked for more of the request body.
    pub(crate) fn waiting_for_client(&self) -> bool {
        self.waiting_for_client.load(Ordering::Relaxed)
    }

    /// The request body failed: the client went away in the middle of it,
    /// or sent what is not a body.
    pub(crate) fn body_failed(&self) {
        self.client_failed.store(true, Ordering::Relaxed);
    }

    /// Whether the request body failed, which fails the attempt it was
    /// being sent with through no fault of the backend.
    pub(crate) fn client_failed(&self) -> bool {
        self.client_failed.load(Ordering::Relaxed)
    }

    /// Whether the request has been sent in full. Only the tests ask: the
    /// deadline ([`SendProgress::response_deadline`]) is what tells.
    #[cfg(test)]
    pub(crate) fn request_complete(&self) -> bool {
        self.completed_ms.load(Ordering::Relaxed) != NOT_COMPLETED
    }

    /// The instant by which the response head must have arrived.
    pub(crate) fn response_deadline(&self, timeouts: &TimeoutsConfig) -> Instant {
        let since_start = |ms: u64| self.started + Duration::from_millis(ms);
        let first_byte =
            since_start(self.last_sent_ms.load(Ordering::Relaxed)) + timeouts.upstream_first_byte;
        match self.completed_ms.load(Ordering::Relaxed) {
            NOT_COMPLETED => first_byte,
            completed => first_byte.min(since_start(completed) + timeouts.request_total),
        }
    }

    /// Resolves once the backend is overdue. Sending more of the request
    /// while this is pending moves the deadline, which is read again on
    /// waking.
    pub(crate) async fn overdue(&self, timeouts: &TimeoutsConfig) {
        loop {
            let deadline = self.response_deadline(timeouts);
            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline.into()).await;
        }
    }
}

/// A request body on its way to a backend: the bytes read from it are added
/// to a shared counter, and its progress and end are noted on a
/// [`SendProgress`], as is whether the client had nothing to give when last
/// asked for more.
#[derive(Debug)]
pub(crate) struct CountedBody<B> {
    inner: B,
    bytes: Arc<AtomicU64>,
    progress: Arc<SendProgress>,
}

impl<B: Body> CountedBody<B> {
    /// `inner`, counting its bytes in `bytes` and its progress in
    /// `progress`.
    pub(crate) fn new(inner: B, bytes: Arc<AtomicU64>, progress: Arc<SendProgress>) -> Self {
        // A body that is empty from the start is never polled.
        if inner.is_end_stream() {
            progress.body_ended(Instant::now());
        }
        CountedBody {
            inner,
            bytes,
            progress,
        }
    }
}

impl<B> Body for CountedBody<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        let this = &mut *self;
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        this.progress.body_polled(polled.is_pending());
        let frame = ready!(polled);
        match &frame {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    this.bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
                if this.inner.is_end_stream() {
                    this.progress.body_ended(Instant::now());
                } else {
                    this.progress.body_progressed(Instant::now());
                }
            }
            Some(Err(_)) => this.progress.body_failed(),
            None => this.progress.body_ended(Instant::now()),
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
#[path = "progress_test.rs"]
mod tests;
