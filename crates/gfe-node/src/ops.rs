//! The operations HTTP server: `/healthz`, `/readyz`, `/metrics`.

use crate::kernel::KernelView;
use crate::logging::Log;
use bytes::Bytes;
use gfe_metrics::{GfeMetrics, LogDestinationLabel};
use gfe_proxy::ProxyShared;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;

/// Shared readiness state for the ops server.
pub struct OpsState {
    pub metrics: Arc<GfeMetrics>,
    pub ready: Arc<AtomicBool>,
    pub shared: Arc<ProxyShared>,
    /// The kernel's view, when attached.
    pub kernel: Option<Arc<KernelView>>,
    /// The node's log, for what it has lost.
    pub log: Arc<Log>,
}

/// The socket the ops server listens on.
///
/// `inherited` is a socket that already listens, with the address it is
/// configured on: it is used instead of binding one if that address is
/// `addr`, and closed otherwise.
pub async fn listen(
    addr: SocketAddr,
    inherited: Option<(SocketAddr, std::net::TcpListener)>,
) -> std::io::Result<TcpListener> {
    let listener = match inherited {
        Some((configured_on, socket)) if configured_on == addr => {
            socket.set_nonblocking(true)?;
            TcpListener::from_std(socket)?
        }
        _ => TcpListener::bind(addr).await?,
    };
    tracing::info!(%addr, "ops server listening (/healthz /readyz /metrics)");
    Ok(listener)
}

/// Serve the ops endpoints on `listener` until `stop` flips to `true`, which
/// is when another process has taken the socket over. Requests already
/// accepted are still answered.
pub async fn serve(
    listener: Arc<TcpListener>,
    state: Arc<OpsState>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        let accepted = tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break;
                }
                continue;
            }
            accepted = listener.accept() => accepted,
        };
        let (stream, _peer) = match accepted {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "ops accept error");
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                let state = state.clone();
                async move { handle(state, req.uri().path()).await }
            });
            let _ = auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await;
        });
    }
}

async fn handle(state: Arc<OpsState>, path: &str) -> Result<Response<Full<Bytes>>, Infallible> {
    let resp = match path {
        "/healthz" => text(StatusCode::OK, "ok"),
        "/readyz" => {
            let ready =
                state.ready.load(Ordering::SeqCst) && !state.shared.draining.load(Ordering::SeqCst);
            if ready {
                text(StatusCode::OK, "ready")
            } else {
                text(StatusCode::SERVICE_UNAVAILABLE, "not ready")
            }
        }
        "/metrics" => {
            let runtime = tokio::runtime::Handle::current().metrics();
            let process = &state.metrics.process;
            process.runtime_workers.set(runtime.num_workers() as i64);
            process
                .runtime_alive_tasks
                .set(runtime.num_alive_tasks() as i64);
            process
                .runtime_global_queue_depth
                .set(runtime.global_queue_depth() as i64);
            // The upstream client keeps its own count; sample it like the
            // runtime, when asked.
            let upstream = &state.shared.upstream;
            let proxy = &state.metrics.proxy;
            proxy
                .upstream_connections
                .set(upstream.open_connections() as i64);
            if let Some(max) = upstream.max_connections() {
                proxy.upstream_connections_limit.set(max as i64);
            }
            if let Some(kernel) = &state.kernel {
                let lost = i64::try_from(kernel.lost_events()).unwrap_or(i64::MAX);
                state.metrics.kernel.ebpf_lost_events.set(lost);
            }
            for (destination, lost) in state.log.lost_lines() {
                process
                    .log_lost_lines
                    .get_or_create(&LogDestinationLabel {
                        destination: destination.to_string(),
                    })
                    .set(i64::try_from(lost).unwrap_or(i64::MAX));
            }
            let body = state.metrics.encode();
            let mut r = Response::new(Full::new(Bytes::from(body)));
            r.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static(
                    "application/openmetrics-text; version=1.0.0; charset=utf-8",
                ),
            );
            r
        }
        _ => text(StatusCode::NOT_FOUND, "not found"),
    };
    Ok(resp)
}

fn text(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(format!("{body}\n"))));
    *r.status_mut() = status;
    r
}
