//! Serving one established connection, HTTP/1.1 or HTTP/2, until it ends.
//!
//! [`serve`] takes a byte stream that is already established (accepted,
//! and with TLS already terminated if there is any) and answers the
//! requests that arrive on it with a [`Handler`]. Which protocol the client
//! speaks is told by its first bytes: the HTTP/2 connection preface means
//! HTTP/2 (prior knowledge), anything else HTTP/1.1. Accepting connections,
//! socket options, TLS and what a request is answered with are the caller's
//! business; this module returns how the connection ended ([`Closed`]) and
//! leaves metrics and logs to the caller.
//!
//! A connection is held to a few timers ([`Options`]). The first request
//! head must be complete within `header_timeout`, else the connection is
//! closed ([`CloseReason::HeaderTimeout`]). After that, a request is *in
//! flight* from the moment its head is read until its response body has
//! been sent to the end or dropped; a connection with no request in flight
//! for `idle_timeout` is shut down gracefully ([`CloseReason::IdleTimeout`]):
//! an HTTP/1.1 connection is closed between requests, an HTTP/2 client is
//! sent a `GOAWAY` and the streams it has open are finished first. On
//! HTTP/1.1 the wait for each later request head, including one sent
//! slowly, is bounded by `idle_timeout` too. An HTTP/2 client silent for
//! `idle_timeout` is sent a PING, and if it does not acknowledge it within
//! `keep_alive_timeout` it is taken for gone and the connection is closed
//! ([`CloseReason::ClientUnresponsive`]). A connection shut down for being
//! idle that has not finished within [`CLOSE_GRACE`] is closed outright,
//! still as [`CloseReason::IdleTimeout`].
//!
//! The caller drains a connection by sending `true` on the `drain` channel
//! (or by dropping its sender). The client is then asked to leave in a way
//! that loses no request. A connection with a request in flight is shut
//! down gracefully at once: the request is answered, HTTP/1.1 responses
//! carry `Connection: close` and HTTP/2 clients get a `GOAWAY`. A
//! connection with none in flight is given `drain_idle_grace` to send one
//! more, because closing it at once would race with a request already on
//! its way; that request is answered (with `Connection: close` on
//! HTTP/1.1), and once the grace is over a connection still without one is
//! shut down gracefully. Either way it ends with [`CloseReason::Drain`],
//! unless the client does not leave: once no request has been in flight
//! for `idle_timeout`, it is closed outright as [`CloseReason::IdleTimeout`].
//!
//! A connection also ends when the client closes it ([`CloseReason::Closed`]),
//! leaves in the middle of a message or resets it
//! ([`CloseReason::ClientAbort`]), or sends what is not HTTP
//! ([`CloseReason::ProtocolError`]; an HTTP/1.1 client is answered `400`,
//! or `431` for a head over `max_header_bytes`, first). And it ends when
//! the caller drops the future [`serve`] returns: the socket is closed and
//! the requests in flight are cancelled. Nothing here outlives that future
//! holding the connection open.
//!
//! The wire protocols are hyper's. HTTP/2 streams are run on tasks of
//! their own, so that one slow request does not hold up the others; such a
//! task ends with its stream, and at the latest when the connection does.
mod activity;

use crate::body::{BoxBody, Incoming};
use activity::{ConnActivity, InFlightBody, Verdict};
use http::header::{CONNECTION, HeaderValue};
use http::{Request, Response, Version};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tokio::time::Instant;

/// How long a connection shut down for being idle may take to finish before
/// it is closed outright.
pub const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// The smallest `max_header_bytes` a connection can be held to: hyper's
/// HTTP/1.1 reads into a buffer of at least this size.
pub const MIN_HEADER_BYTES: usize = 8192;

/// What a served connection is held to.
///
/// A valid set of options ([`Options::validate`]) has every duration longer
/// than zero, `max_header_bytes` at least [`MIN_HEADER_BYTES`] and room for
/// at least one HTTP/2 stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// The first request head must be complete this long after serving
    /// began.
    pub header_timeout: Duration,
    /// With no request in flight for this long the connection is shut down,
    /// in a way that loses no request. An HTTP/1.1 client is given this long
    /// to send each request head after the first; an HTTP/2 client silent
    /// for this long is sent a PING.
    pub idle_timeout: Duration,
    /// How long an HTTP/2 client has to acknowledge a PING.
    pub keep_alive_timeout: Duration,
    /// Once asked to drain, how long a connection with no request in flight
    /// waits for one more before it is shut down.
    pub drain_idle_grace: Duration,
    /// The largest request head accepted, in bytes. A larger HTTP/1.1 head
    /// is refused with `431`; on HTTP/2 it bounds the decoded header list.
    pub max_header_bytes: usize,
    /// How many streams an HTTP/2 client may have open at once. It is what
    /// the client is told in its SETTINGS, and a stream over it is refused.
    pub max_concurrent_streams: u32,
}

impl Options {
    /// Whether these options can be served with, and if not, why.
    pub fn validate(&self) -> Result<(), InvalidOptions> {
        let durations = [
            ("header_timeout", self.header_timeout),
            ("idle_timeout", self.idle_timeout),
            ("keep_alive_timeout", self.keep_alive_timeout),
            ("drain_idle_grace", self.drain_idle_grace),
        ];
        if let Some((name, _)) = durations.iter().find(|(_, d)| d.is_zero()) {
            return Err(InvalidOptions::ZeroDuration(name));
        }
        if self.max_header_bytes < MIN_HEADER_BYTES {
            return Err(InvalidOptions::HeaderBytesTooSmall(self.max_header_bytes));
        }
        if self.max_concurrent_streams == 0 {
            return Err(InvalidOptions::NoStreams);
        }
        Ok(())
    }
}

/// Why a set of [`Options`] cannot be served with.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidOptions {
    /// The named duration is zero, which would expire at once.
    #[error("{0} must be longer than zero")]
    ZeroDuration(&'static str),
    /// `max_header_bytes` is below [`MIN_HEADER_BYTES`].
    #[error("max_header_bytes must be at least {MIN_HEADER_BYTES}, got {0}")]
    HeaderBytesTooSmall(usize),
    /// `max_concurrent_streams` is zero, which would refuse every stream.
    #[error("max_concurrent_streams must be at least 1")]
    NoStreams,
}

/// Whoever answers the requests of a connection.
///
/// One handler is given per connection, so it may carry what the caller
/// knows about that connection (its peer, its TLS parameters). It is called
/// once per request, concurrently for the streams of an HTTP/2 connection.
pub trait Handler: Send + Sync + 'static {
    /// The response to `request`. The response is sent as it is, except
    /// that `Connection: close` is added to an HTTP/1.1 response while the
    /// connection drains. Its body is sent until it ends or the client goes
    /// away; it is dropped either way.
    fn handle(&self, request: Request<Incoming>) -> impl Future<Output = Response<BoxBody>> + Send;
}

/// How a served connection ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Closed {
    /// Why it ended.
    pub reason: CloseReason,
    /// How many requests reached the handler.
    pub requests: u64,
    /// The error it ended with, as text, if it ended with one.
    pub error: Option<String>,
}

/// Why a served connection ended.
///
/// There is no label text here on purpose: whoever reports it maps each
/// reason to its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloseReason {
    /// The client closed it, or it ended in an orderly way.
    Closed,
    /// It was asked to leave because of the drain, and it did.
    Drain,
    /// No request was in flight for the idle timeout, or an HTTP/1.1 client
    /// took longer than that to send a request head after the first.
    IdleTimeout,
    /// The first request head was not complete within the header timeout.
    HeaderTimeout,
    /// The client reset the connection, or went away in the middle of a
    /// message.
    ClientAbort,
    /// The client did not acknowledge an HTTP/2 PING in time, or the
    /// transport gave up on it.
    ClientUnresponsive,
    /// The client sent what is not HTTP, or a head over the limit.
    ProtocolError,
    /// Anything else; [`Closed::error`] says what.
    Error,
}

/// Serve `io` until the connection ends or, once `drain` turns `true` (or
/// its sender is dropped), until the client has been asked to leave and has.
///
/// The lifecycle, timers and drain protocol are those the module
/// documentation describes. Dropping the returned future closes the
/// connection at once. Invalid `options` close it at once too, with
/// [`CloseReason::Error`]; check them with [`Options::validate`] when they
/// are configured.
pub async fn serve<S, H>(
    io: S,
    handler: Arc<H>,
    options: Options,
    mut drain: watch::Receiver<bool>,
) -> Closed
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: Handler,
{
    if let Err(invalid) = options.validate() {
        return Closed {
            reason: CloseReason::Error,
            requests: 0,
            error: Some(invalid.to_string()),
        };
    }
    let activity = ConnActivity::new(Instant::now(), options.header_timeout, options.idle_timeout);
    // Set once a response has told an HTTP/1.1 client to close the
    // connection.
    let told_to_close = Arc::new(AtomicBool::new(false));
    // Set once the connection has carried an HTTP/2 request.
    let http2 = Arc::new(AtomicBool::new(false));

    let service = service_fn({
        let activity = activity.clone();
        let told_to_close = told_to_close.clone();
        let http2 = http2.clone();
        let drain = drain.clone();
        move |request: Request<Incoming>| {
            let in_flight = activity.begin_request();
            let handler = handler.clone();
            let told_to_close = told_to_close.clone();
            let drain = drain.clone();
            // HTTP/2 has no header for it: its clients are sent a GOAWAY.
            let http1 = request.version() < Version::HTTP_2;
            if !http1 {
                http2.store(true, Ordering::Relaxed);
            }
            async move {
                let mut response = handler.handle(request).await;
                if http1 && is_draining(&drain) {
                    response
                        .headers_mut()
                        .insert(CONNECTION, HeaderValue::from_static("close"));
                    told_to_close.store(true, Ordering::Relaxed);
                }
                Ok::<_, Infallible>(response.map(|body| InFlightBody::new(body, in_flight)))
            }
        }
    });
    let builder = http_builder(&options);
    let connection = builder.serve_connection(TokioIo::new(io), service);
    tokio::pin!(connection);

    // A receiver whose value was already seen still has it looked at once,
    // so that a connection served after the drain began is drained too.
    drain.mark_changed();
    // First looked at when either timer could first be due.
    let watchdog = tokio::time::sleep(options.header_timeout.min(options.idle_timeout));
    tokio::pin!(watchdog);
    // Why the connection was shut down gracefully, once it has been.
    let mut shut_down_for: Option<CloseReason> = None;
    let mut draining = false;
    // While draining with no request in flight: until when one more is
    // waited for.
    let mut leave_by: Option<Instant> = None;

    let (reason, error) = loop {
        tokio::select! {
            // In this order, always: the connection is looked at before its
            // timers. When the runtime is late, bytes that arrived in time
            // and a timer that has since expired are found together, and
            // what the client sent in time must be seen before the timer
            // decides that it sent nothing.
            biased;
            result = connection.as_mut() => break match result {
                Ok(()) if told_to_close.load(Ordering::Relaxed) => (CloseReason::Drain, None),
                Ok(()) => (shut_down_for.unwrap_or(CloseReason::Closed), None),
                Err(e) => match shut_down_for {
                    // Shut down before the client said which protocol it
                    // speaks, which hyper reports as an error.
                    Some(reason) if is_cancelled(e.as_ref()) => (reason, None),
                    _ => {
                        tracing::debug!(error = %e, "connection closed with error");
                        let http2 = http2.load(Ordering::Relaxed);
                        (error_close_reason(e.as_ref(), http2), Some(e.to_string()))
                    }
                },
            },
            changed = drain.changed(), if !draining => {
                draining = changed.is_err() || *drain.borrow();
                if draining && shut_down_for.is_none() {
                    if activity.has_request_in_flight() {
                        connection.as_mut().graceful_shutdown();
                        shut_down_for = Some(CloseReason::Drain);
                    } else {
                        let deadline = Instant::now() + options.drain_idle_grace;
                        leave_by = Some(deadline);
                        if deadline < watchdog.deadline() {
                            watchdog.as_mut().reset(deadline);
                        }
                    }
                }
            }
            () = watchdog.as_mut() => {
                let now = Instant::now();
                if shut_down_for.is_none() && leave_by.is_some_and(|deadline| now >= deadline) {
                    connection.as_mut().graceful_shutdown();
                    shut_down_for = Some(CloseReason::Drain);
                }
                let next_check = match activity.verdict(now) {
                    Verdict::CheckAgainAt(at) => at,
                    Verdict::IdleTimeout if shut_down_for.is_none() => {
                        connection.as_mut().graceful_shutdown();
                        shut_down_for = Some(CloseReason::IdleTimeout);
                        now + CLOSE_GRACE
                    }
                    // Shut down gracefully already, and still not gone.
                    Verdict::IdleTimeout => break (CloseReason::IdleTimeout, None),
                    Verdict::HeaderTimeout => break (CloseReason::HeaderTimeout, None),
                };
                let next_check = match leave_by {
                    Some(deadline) if shut_down_for.is_none() => next_check.min(deadline),
                    _ => next_check,
                };
                watchdog.as_mut().reset(next_check);
            }
        }
    };
    Closed {
        reason,
        requests: activity.requests(),
        error,
    }
}

/// Whether the connection `drain` belongs to is draining: it is once `true`
/// was sent, or once the sender is gone.
fn is_draining(drain: &watch::Receiver<bool>) -> bool {
    drain.has_changed().is_err() || *drain.borrow()
}

/// Whether `error` is how hyper reports a connection shut down before its
/// protocol was known: an I/O error of kind `Interrupted`, which no socket
/// returns (tokio retries those reads itself).
fn is_cancelled(error: &(dyn std::error::Error + 'static)) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::Interrupted)
}

/// Why a connection that ended with `error` did so. `http2` tells whether
/// the connection carried HTTP/2 requests.
fn error_close_reason(error: &(dyn std::error::Error + 'static), http2: bool) -> CloseReason {
    if let Some(http) = error.downcast_ref::<hyper::Error>() {
        if http.is_timeout() {
            // hyper runs one timer per protocol: on HTTP/1.1 the wait for a
            // request head, for `idle_timeout`; on HTTP/2 the wait for a PING
            // acknowledgement.
            return if http2 {
                CloseReason::ClientUnresponsive
            } else {
                CloseReason::IdleTimeout
            };
        }
        if http.is_parse() || http.is_parse_too_large() {
            return CloseReason::ProtocolError;
        }
        if http.is_incomplete_message() {
            return CloseReason::ClientAbort;
        }
    }
    let mut cause = Some(error);
    while let Some(current) = cause {
        if let Some(io) = current.downcast_ref::<std::io::Error>() {
            return match io.kind() {
                std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof => CloseReason::ClientAbort,
                // TCP keepalive (or retransmission) gave up on the peer.
                std::io::ErrorKind::TimedOut => CloseReason::ClientUnresponsive,
                _ => CloseReason::Error,
            };
        }
        cause = current.source();
    }
    CloseReason::Error
}

/// hyper's server, both protocols, held to `options`.
fn http_builder(options: &Options) -> auto::Builder<TokioExecutor> {
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        // hyper starts this timer as soon as it waits for a request head, so
        // on HTTP/1.1 it bounds the keep-alive wait and a slowly sent head
        // together. The first head is bounded tighter by the watchdog.
        .header_read_timeout(options.idle_timeout)
        .max_buf_size(options.max_header_bytes);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Some(options.idle_timeout))
        .keep_alive_timeout(options.keep_alive_timeout)
        .max_concurrent_streams(options.max_concurrent_streams)
        .max_header_list_size(u32::try_from(options.max_header_bytes).unwrap_or(u32::MAX));
    builder
}

#[cfg(test)]
#[path = "server_test.rs"]
mod tests;
