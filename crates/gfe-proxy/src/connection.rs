//! Per-connection handling: optional TLS handshake (with SNI capture), then
//! HTTP serving via hyper's protocol-auto-detecting server.

use crate::service::handle_request;
use crate::{ConnCtx, ProxyShared};
use gfe_metrics::{ListenerLabel, RejectLabel, TlsResultLabel};
use gfe_types::Listener;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::ServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

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

/// Run the HTTP server (h1/h2 auto-detected) over the given IO.
async fn serve_io<S>(stream: S, ctx: Arc<ConnCtx>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let svc = service_fn(move |req| {
        let ctx = ctx.clone();
        async move { handle_request(ctx, req).await }
    });
    let builder = auto::Builder::new(TokioExecutor::new());
    if let Err(e) = builder.serve_connection(io, svc).await {
        tracing::debug!(error = %e, "connection closed with error");
    }
}
