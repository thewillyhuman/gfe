//! Per-connection handling: optional TLS handshake (with SNI capture), then
//! HTTP serving via hyper's protocol-auto-detecting server, bounded by the
//! client-side timeouts and limits, and ended in an orderly way when the node
//! drains.

use crate::activity::{ConnActivity, InFlightBody, Verdict};
use crate::conn_record::{ConnRecord, TlsInfo};
use crate::service::handle_request;
use crate::{ConnCtx, ProxyShared};
use arc_swap::ArcSwap;
use gfe_observability::RejectLabel;
use gfe_types::{Listener, TimeoutsConfig};
use hyper::header::{HeaderValue, CONNECTION};
use hyper::service::service_fn;
use hyper::Version;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use rustls::ServerConfig;
use socket2::{SockRef, TcpKeepalive};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

/// How long a connection that was asked to shut down gracefully may take to
/// finish before it is closed outright.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// How long a draining node waits for one more request on a connection that
/// has none in flight: half the drain deadline, which leaves the other half
/// for that request to be answered.
fn idle_grace(timeouts: &TimeoutsConfig) -> Duration {
    timeouts.drain_deadline / 2
}

/// How long an HTTP/2 client has to acknowledge a PING before it is taken for
/// gone. The PING is sent after `client_idle` without a frame from it.
fn keep_alive_timeout(timeouts: &TimeoutsConfig) -> Duration {
    timeouts.client_idle / 4
}

/// How many TCP keepalive probes may go unanswered before the peer is taken
/// for gone.
const KEEPALIVE_PROBES: u32 = 3;

/// Have the kernel probe a peer that has been silent for `client_idle`,
/// every quarter of `client_idle`, and give it up after
/// [`KEEPALIVE_PROBES`] unanswered probes. A client that vanished without
/// FIN or RST then fails the connection even with an HTTP/1 request in
/// flight, which nothing else would notice. A socket that refuses the option
/// is served without it.
fn enable_tcp_keepalive(stream: &TcpStream, timeouts: &TimeoutsConfig) {
    // The kernel counts in whole seconds, and rejects zero.
    let second = Duration::from_secs(1);
    let silence = timeouts.client_idle.max(second);
    // Left to itself the kernel would keep probing for many minutes (nine
    // probes 75 s apart on Linux) before giving the peer up.
    let keepalive = TcpKeepalive::new()
        .with_time(silence)
        .with_interval((timeouts.client_idle / 4).max(second))
        .with_retries(KEEPALIVE_PROBES);
    if let Err(e) = SockRef::from(stream).set_tcp_keepalive(&keepalive) {
        tracing::debug!(error = %e, "cannot enable tcp keepalive");
    }
}

/// Serve a single accepted TCP connection until it ends or, once `drain`
/// flips to `true`, until the client has been asked to leave. The connection
/// is accounted for by a [`ConnRecord`], which reports it when this function
/// returns.
///
/// `listener` is the accepting socket's listener as currently configured:
/// each request is routed by the listener's id at the time it arrives, so a
/// reload that renames the listener does not strand open connections.
pub async fn serve(
    stream: TcpStream,
    peer: SocketAddr,
    listener: Arc<ArcSwap<Listener>>,
    shared: Arc<ProxyShared>,
    tls: Option<Arc<ServerConfig>>,
    drain: watch::Receiver<bool>,
) {
    let _ = stream.set_nodelay(true);
    enable_tcp_keepalive(&stream, &shared.timeouts);
    let mut record = ConnRecord::open(
        shared.clone(),
        &listener.load(),
        stream.local_addr().ok(),
        peer,
    );
    let stream = record.count_traffic(stream);
    let mut ctx = ConnCtx {
        shared: shared.clone(),
        listener_id: listener.load().id.clone(),
        is_tls: tls.is_some(),
        client_ip: peer.ip(),
        client_port: peer.port(),
        sni: None,
        tls: None,
    };

    let closed = match tls {
        Some(cfg) => {
            let handshake_started = Instant::now();
            let handshake = TlsAcceptor::from(cfg).accept(stream);
            match tokio::time::timeout(shared.timeouts.tls_handshake, handshake).await {
                Ok(Ok(tls_stream)) => {
                    let session = tls_stream.get_ref().1;
                    ctx.sni = session.server_name().map(str::to_string);
                    ctx.tls = Some(TlsInfo::of(session));
                    record.tls_established(
                        TlsInfo::of(session),
                        ctx.sni.clone(),
                        handshake_started.elapsed(),
                    );
                    serve_io(tls_stream, ctx, listener, drain).await
                }
                Ok(Err(e)) => {
                    tracing::debug!(error = %e, "tls handshake failed");
                    record.tls_failed(&e);
                    return;
                }
                Err(_) => {
                    shared
                        .metrics
                        .proxy
                        .connections_rejected
                        .get_or_create(&RejectLabel {
                            reason: "handshake_timeout".into(),
                        })
                        .inc();
                    record.tls_timed_out();
                    return;
                }
            }
        }
        None => serve_io(stream, ctx, listener, drain).await,
    };
    record.closed(closed.reason, closed.requests, closed.error);
}

/// How a served connection ended.
struct Closed {
    reason: &'static str,
    requests: u64,
    error: Option<String>,
}

/// Run the HTTP server (h1/h2 auto-detected) over the given IO until the
/// connection ends, a client-side timeout closes it, or the node drains:
///
/// * `request_header` — the first request head must arrive within this long
///   of the connection being established, else the connection is dropped.
/// * `client_idle` — a connection with no request in flight for this long is
///   shut down gracefully (HTTP/2 clients get a `GOAWAY`). An HTTP/2 client
///   silent for this long is sent a PING, and the connection is closed if
///   the PING is not acknowledged within [`keep_alive_timeout`].
/// * drain — once `drain` flips to `true` the client is asked to leave, in a
///   way that loses no request. A connection with a request in flight is shut
///   down gracefully at once: the request is answered, and HTTP/2 clients get
///   a `GOAWAY`. A connection with none is given [`idle_grace`] to send one
///   more, because closing it right away would race with a request already
///   on its way; an HTTP/1 request is then answered with `Connection: close`.
///
/// Each request is handled with a copy of `ctx` naming `listener`'s id as
/// it is when the request arrives.
async fn serve_io<S>(
    stream: S,
    ctx: ConnCtx,
    listener: Arc<ArcSwap<Listener>>,
    mut drain: watch::Receiver<bool>,
) -> Closed
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let shared = ctx.shared.clone();
    let activity = ConnActivity::new(Instant::now());
    // Set once a response has told an HTTP/1 client to close the connection.
    let told_to_close = Arc::new(AtomicBool::new(false));
    // Set once the connection has carried an HTTP/2 request.
    let http2 = Arc::new(AtomicBool::new(false));

    let io = TokioIo::new(stream);
    let svc = service_fn({
        let activity = activity.clone();
        let shared = shared.clone();
        let told_to_close = told_to_close.clone();
        let http2 = http2.clone();
        move |req| {
            let ctx = Arc::new(ConnCtx {
                listener_id: listener.load().id.clone(),
                ..ctx.clone()
            });
            let in_flight = activity.begin_request();
            let shared = shared.clone();
            let told_to_close = told_to_close.clone();
            // HTTP/2 has no header for it: its clients are sent a GOAWAY.
            let http1 = req.version() < Version::HTTP_2;
            if !http1 {
                http2.store(true, Ordering::Relaxed);
            }
            async move {
                let mut resp = handle_request(ctx, req).await?;
                if http1 && shared.draining.load(Ordering::Relaxed) {
                    resp.headers_mut()
                        .insert(CONNECTION, HeaderValue::from_static("close"));
                    told_to_close.store(true, Ordering::Relaxed);
                }
                Ok::<_, Infallible>(resp.map(|body| InFlightBody::new(body, in_flight)))
            }
        }
    });
    let builder = http_builder(&shared);
    let conn = builder.serve_connection(io, svc);
    tokio::pin!(conn);

    let watchdog = tokio::time::sleep(shared.timeouts.request_header);
    tokio::pin!(watchdog);
    // Why the connection was shut down gracefully, once it has been.
    let mut shut_down_for: Option<&'static str> = None;
    let mut draining = false;
    // While draining with no request in flight: until when one more is
    // waited for.
    let mut leave_by: Option<Instant> = None;

    let (reason, error) = loop {
        tokio::select! {
            result = conn.as_mut() => break match result {
                Ok(()) if told_to_close.load(Ordering::Relaxed) => ("drain", None),
                Ok(()) => (shut_down_for.unwrap_or("closed"), None),
                Err(e) => {
                    tracing::debug!(error = %e, "connection closed with error");
                    let reason = error_close_reason(e.as_ref(), http2.load(Ordering::Relaxed));
                    (reason, Some(e.to_string()))
                }
            },
            changed = drain.changed(), if !draining => {
                // The sender going away means the node is going away, too.
                draining = changed.is_err() || *drain.borrow();
                if draining && shut_down_for.is_none() {
                    if activity.has_request_in_flight() {
                        conn.as_mut().graceful_shutdown();
                        shut_down_for = Some("drain");
                    } else {
                        let deadline = Instant::now() + idle_grace(&shared.timeouts);
                        leave_by = Some(deadline);
                        if tokio::time::Instant::from_std(deadline) < watchdog.deadline() {
                            watchdog.as_mut().reset(deadline.into());
                        }
                    }
                }
            }
            _ = watchdog.as_mut() => {
                let now = Instant::now();
                if shut_down_for.is_none() && leave_by.is_some_and(|deadline| now >= deadline) {
                    conn.as_mut().graceful_shutdown();
                    shut_down_for = Some("drain");
                }
                let next_check = match activity.verdict(now, &shared.timeouts) {
                    Verdict::CheckAgainAt(at) => at,
                    Verdict::IdleTimeout if shut_down_for.is_none() => {
                        conn.as_mut().graceful_shutdown();
                        shut_down_for = Some("idle_timeout");
                        now + CLOSE_GRACE
                    }
                    Verdict::IdleTimeout => break ("idle_timeout", None),
                    Verdict::HeaderTimeout => break ("header_timeout", None),
                };
                let next_check = match leave_by {
                    Some(deadline) if shut_down_for.is_none() => next_check.min(deadline),
                    _ => next_check,
                };
                watchdog.as_mut().reset(next_check.into());
            }
        }
    };
    Closed {
        reason,
        requests: activity.requests(),
        error,
    }
}

/// Why a connection that ended with an error did so, as a bounded label
/// value. The error text itself goes to the connection log. `http2` tells
/// whether the connection carried HTTP/2 requests.
fn error_close_reason(error: &(dyn std::error::Error + 'static), http2: bool) -> &'static str {
    if let Some(http) = error.downcast_ref::<hyper::Error>() {
        if http.is_timeout() {
            // hyper runs one timer per protocol: on HTTP/1 the wait for a
            // request head, for `client_idle`; on HTTP/2 the wait for a PING
            // acknowledgement.
            return if http2 {
                "client_unresponsive"
            } else {
                "idle_timeout"
            };
        }
        if http.is_parse() || http.is_parse_too_large() {
            return "protocol_error";
        }
        if http.is_incomplete_message() {
            return "client_abort";
        }
    }
    let mut cause = Some(error);
    while let Some(current) = cause {
        if let Some(io) = current.downcast_ref::<std::io::Error>() {
            return match io.kind() {
                std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof => "client_abort",
                // TCP keepalive (or retransmission) gave up on the peer.
                std::io::ErrorKind::TimedOut => "client_unresponsive",
                _ => "error",
            };
        }
        cause = current.source();
    }
    "error"
}

/// The hyper server builder with the configured client-side limits applied.
fn http_builder(shared: &ProxyShared) -> auto::Builder<TokioExecutor> {
    let max_header_bytes = shared.limits.max_header_bytes;
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        // hyper starts this timer as soon as it waits for a request head, so
        // on HTTP/1 it bounds the keep-alive wait and a slowly sent head
        // together. The first head is bounded tighter by the watchdog.
        .header_read_timeout(shared.timeouts.client_idle)
        .max_buf_size(max_header_bytes);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Some(shared.timeouts.client_idle))
        .keep_alive_timeout(keep_alive_timeout(&shared.timeouts))
        .max_concurrent_streams(shared.limits.max_h2_concurrent_streams)
        .max_header_list_size(u32::try_from(max_header_bytes).unwrap_or(u32::MAX));
    builder
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn accepted_socket_probes_a_peer_silent_for_client_idle() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        let timeouts = TimeoutsConfig {
            client_idle: Duration::from_secs(42),
            ..Default::default()
        };

        enable_tcp_keepalive(&accepted, &timeouts);

        let socket = socket2::SockRef::from(&accepted);
        assert!(socket.keepalive().unwrap());
        assert_eq!(
            socket.tcp_keepalive_time().unwrap(),
            Duration::from_secs(42)
        );
    }

    #[tokio::test]
    async fn accepted_socket_gives_up_on_a_dead_peer_within_client_idle() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        let timeouts = TimeoutsConfig {
            client_idle: Duration::from_secs(40),
            ..Default::default()
        };

        enable_tcp_keepalive(&accepted, &timeouts);

        // Three probes ten seconds apart: gone for 30 s after the 40 s of
        // silence, not for the kernel's default of many minutes.
        let socket = socket2::SockRef::from(&accepted);
        assert_eq!(
            socket.tcp_keepalive_interval().unwrap(),
            Duration::from_secs(10)
        );
        assert_eq!(socket.tcp_keepalive_retries().unwrap(), 3);
    }

    #[test]
    fn a_connection_timed_out_by_tcp_keepalive_is_unresponsive() {
        let error = std::io::Error::from(std::io::ErrorKind::TimedOut);

        assert_eq!(error_close_reason(&error, false), "client_unresponsive");
    }

    #[test]
    fn a_reset_connection_is_a_client_abort() {
        let error = std::io::Error::from(std::io::ErrorKind::ConnectionReset);

        assert_eq!(error_close_reason(&error, true), "client_abort");
    }
}
