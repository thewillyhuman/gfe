//! Per-connection handling: optional TLS handshake (with SNI capture), then
//! HTTP serving via hyper's protocol-auto-detecting server, bounded by the
//! client-side timeouts and limits.

use crate::activity::{ConnActivity, InFlightBody, Verdict};
use crate::service::handle_request;
use crate::{ConnCtx, ProxyShared};
use gfe_metrics::{ListenerLabel, RejectLabel, TlsResultLabel};
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

/// Serve a single accepted TCP connection.
pub async fn serve(
    stream: TcpStream,
    peer: SocketAddr,
    listener: Listener,
    shared: Arc<ProxyShared>,
    tls: Option<Arc<ServerConfig>>,
) {
    let _ = stream.set_nodelay(true);

    shared
        .metrics
        .proxy
        .connections_accepted
        .get_or_create(&ListenerLabel {
            listener: listener.id.to_string(),
        })
        .inc();
    shared.metrics.proxy.connections_active.inc();

    let client_ip = peer.ip();

    match tls {
        Some(cfg) => {
            let acceptor = TlsAcceptor::from(cfg);
            let hs_start = Instant::now();
            let accepted =
                tokio::time::timeout(shared.timeouts.tls_handshake, acceptor.accept(stream)).await;
            match accepted {
                Ok(Ok(tls_stream)) => {
                    shared
                        .metrics
                        .proxy
                        .tls_handshakes
                        .get_or_create(&TlsResultLabel {
                            result: "ok".into(),
                        })
                        .inc();
                    shared
                        .metrics
                        .proxy
                        .tls_handshake_duration_seconds
                        .observe(hs_start.elapsed().as_secs_f64());
                    let sni = tls_stream.get_ref().1.server_name().map(|s| s.to_string());
                    let ctx = Arc::new(ConnCtx {
                        shared: shared.clone(),
                        listener_id: listener.id.clone(),
                        is_tls: true,
                        client_ip,
                        sni,
                    });
                    serve_io(tls_stream, ctx).await;
                }
                Ok(Err(e)) => {
                    shared
                        .metrics
                        .proxy
                        .tls_handshakes
                        .get_or_create(&TlsResultLabel {
                            result: "failed".into(),
                        })
                        .inc();
                    tracing::debug!(error = %e, "tls handshake failed");
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
                }
            }
        }
        None => {
            let ctx = Arc::new(ConnCtx {
                shared: shared.clone(),
                listener_id: listener.id.clone(),
                is_tls: false,
                client_ip,
                sni: None,
            });
            serve_io(stream, ctx).await;
        }
    }

    shared.metrics.proxy.connections_active.dec();
}

/// Run the HTTP server (h1/h2 auto-detected) over the given IO until the
/// connection ends or a client-side timeout closes it:
///
/// * `request_header` — the first request head must arrive within this long
///   of the connection being established, else the connection is dropped.
/// * `client_idle` — a connection with no request in flight for this long is
///   shut down gracefully (HTTP/2 clients get a `GOAWAY`).
async fn serve_io<S>(stream: S, ctx: Arc<ConnCtx>)
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
    let mut closing = false;

    loop {
        tokio::select! {
            result = conn.as_mut() => {
                if let Err(e) = result {
                    tracing::debug!(error = %e, "connection closed with error");
                }
                return;
            }
            _ = watchdog.as_mut() => {
                let now = Instant::now();
                let next_check = match activity.verdict(now, &shared.timeouts) {
                    Verdict::CheckAgainAt(at) => at,
                    Verdict::IdleTimeout if !closing => {
                        tracing::debug!("client idle timeout, shutting connection down");
                        conn.as_mut().graceful_shutdown();
                        closing = true;
                        now + CLOSE_GRACE
                    }
                    verdict => {
                        tracing::debug!(?verdict, "client timeout, closing connection");
                        return;
                    }
                };
                watchdog.as_mut().reset(next_check.into());
            }
        }
    }
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
