//! Per-connection handling: optional TLS handshake (with SNI capture), then
//! HTTP serving via hyper's protocol-auto-detecting server, bounded by the
//! client-side timeouts and limits.

use crate::activity::{ConnActivity, InFlightBody, Verdict};
use crate::conn_record::{ConnRecord, TlsInfo};
use crate::service::handle_request;
use crate::{ConnCtx, ProxyShared};
use gfe_metrics::RejectLabel;
use gfe_types::Listener;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use rustls::ServerConfig;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

/// How long a connection that was asked to shut down gracefully may take to
/// finish before it is closed outright.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// Serve a single accepted TCP connection. The connection is accounted for
/// by a [`ConnRecord`], which reports it when this function returns.
pub async fn serve(
    stream: TcpStream,
    peer: SocketAddr,
    listener: Arc<Listener>,
    shared: Arc<ProxyShared>,
    tls: Option<Arc<ServerConfig>>,
) {
    let _ = stream.set_nodelay(true);
    let mut record = ConnRecord::open(shared.clone(), &listener, stream.local_addr().ok(), peer);
    let stream = record.count_traffic(stream);
    let mut ctx = ConnCtx {
        shared: shared.clone(),
        listener_id: listener.id.clone(),
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
                    serve_io(tls_stream, Arc::new(ctx)).await
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
        None => serve_io(stream, Arc::new(ctx)).await,
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
/// connection ends or a client-side timeout closes it:
///
/// * `request_header` — the first request head must arrive within this long
///   of the connection being established, else the connection is dropped.
/// * `client_idle` — a connection with no request in flight for this long is
///   shut down gracefully (HTTP/2 clients get a `GOAWAY`).
async fn serve_io<S>(stream: S, ctx: Arc<ConnCtx>) -> Closed
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let shared = ctx.shared.clone();
    let activity = ConnActivity::new(Instant::now());

    let io = TokioIo::new(stream);
    let svc = service_fn({
        let activity = activity.clone();
        move |req| {
            let ctx = ctx.clone();
            let in_flight = activity.begin_request();
            async move {
                let resp = handle_request(ctx, req).await?;
                Ok::<_, Infallible>(resp.map(|body| InFlightBody::new(body, in_flight)))
            }
        }
    });
    let builder = http_builder(&shared);
    let conn = builder.serve_connection(io, svc);
    tokio::pin!(conn);

    let watchdog = tokio::time::sleep(shared.timeouts.request_header);
    tokio::pin!(watchdog);
    let mut idle_shutdown = false;

    let (reason, error) = loop {
        tokio::select! {
            result = conn.as_mut() => break match result {
                Ok(()) if idle_shutdown => ("idle_timeout", None),
                Ok(()) => ("closed", None),
                Err(e) => {
                    tracing::debug!(error = %e, "connection closed with error");
                    (error_close_reason(e.as_ref()), Some(e.to_string()))
                }
            },
            _ = watchdog.as_mut() => {
                let now = Instant::now();
                let next_check = match activity.verdict(now, &shared.timeouts) {
                    Verdict::CheckAgainAt(at) => at,
                    Verdict::IdleTimeout if !idle_shutdown => {
                        conn.as_mut().graceful_shutdown();
                        idle_shutdown = true;
                        now + CLOSE_GRACE
                    }
                    Verdict::IdleTimeout => break ("idle_timeout", None),
                    Verdict::HeaderTimeout => break ("header_timeout", None),
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
/// value. The error text itself goes to the connection log.
fn error_close_reason(error: &(dyn std::error::Error + 'static)) -> &'static str {
    if let Some(http) = error.downcast_ref::<hyper::Error>() {
        if http.is_timeout() {
            // hyper's own HTTP/1 timer, which runs for `client_idle`.
            return "idle_timeout";
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
        .max_concurrent_streams(shared.limits.max_h2_concurrent_streams)
        .max_header_list_size(u32::try_from(max_header_bytes).unwrap_or(u32::MAX));
    builder
}
