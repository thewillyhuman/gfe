//! The operations HTTP server: `/healthz`, `/readyz`, `/metrics`.

use crate::kernel::KernelView;
use crate::logging::Log;
use bytes::Bytes;
use gfe_observability::{GfeMetrics, LogDestinationLabel};
use gfe_proxy::ProxyShared;
use http_body_util::Full;
use hyper::header::{HeaderValue, CONNECTION};
use hyper::service::service_fn;
use hyper::{Response, StatusCode, Version};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};

/// How many connections the ops server serves at once. Probes and scrapes
/// need a handful; the node's file descriptors are for the proxy. A
/// connection over the cap is closed at once.
const MAX_CONNECTIONS: usize = 64;

/// How long a client has to send a request head, and how long a connection
/// it keeps may wait idle for the next one.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to wait after `accept` fails before trying again. It fails
/// again at once while its cause (no file descriptor left) lasts.
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(100);

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
/// is when another process has taken the socket over. Connections already
/// accepted are still answered, `/readyz` as ready, and then closed, so that
/// a client that keeps one asks the new process next.
pub async fn serve(
    listener: Arc<TcpListener>,
    state: Arc<OpsState>,
    mut stop: watch::Receiver<bool>,
) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
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
                tokio::time::sleep(ACCEPT_ERROR_PAUSE).await;
                continue;
            }
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            tracing::debug!("ops connection over the cap closed");
            continue;
        };
        let state = state.clone();
        let mut stop = stop.clone();
        tokio::spawn(async move {
            // Taken back when the connection closes.
            let _slot = slot;
            // hyper learns the protocol from the first bytes and starts its
            // timer only once it knows it: a client that sends nothing would
            // be waited for for ever.
            if tokio::time::timeout(HEADER_READ_TIMEOUT, stream.readable())
                .await
                .is_err()
            {
                return;
            }
            let io = TokioIo::new(stream);
            // Set once a request has been answered here: shutting a
            // connection down before then could close it on a request
            // already on its way.
            let answered = Arc::new(AtomicBool::new(false));
            let svc = service_fn({
                let answered = answered.clone();
                let stop = stop.clone();
                move |req| {
                    let state = state.clone();
                    let answered = answered.clone();
                    let handed_over = *stop.borrow();
                    // HTTP/2 has no such header: its clients get a GOAWAY.
                    let http1 = req.version() < Version::HTTP_2;
                    async move {
                        let mut resp = handle(state, req.uri().path(), handed_over).await?;
                        if handed_over && http1 {
                            resp.headers_mut()
                                .insert(CONNECTION, HeaderValue::from_static("close"));
                        }
                        answered.store(true, Ordering::SeqCst);
                        Ok::<_, Infallible>(resp)
                    }
                }
            });
            let mut builder = auto::Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT);
            let conn = builder.serve_connection(io, svc);
            tokio::pin!(conn);
            tokio::select! {
                _ = conn.as_mut() => {}
                // Clients are moved to the process that serves now: one that
                // has been answered here is shut down gracefully, and one
                // that has not is told to close with its first answer.
                () = stopped(&mut stop) => {
                    if answered.load(Ordering::SeqCst) {
                        conn.as_mut().graceful_shutdown();
                    }
                    let _ = conn.await;
                }
            }
        });
    }
}

/// Returns once `stop` flips to `true`, or its sender is gone.
async fn stopped(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|stopped| *stopped).await;
}

/// Answer a request for `path`. `handed_over` is whether another process has
/// taken the ops socket over, which it does only once it is ready: the
/// address is then ready whatever this process is doing.
async fn handle(
    state: Arc<OpsState>,
    path: &str,
    handed_over: bool,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let resp = match path {
        "/healthz" => text(StatusCode::OK, "ok"),
        "/readyz" => {
            let ready = handed_over
                || state.ready.load(Ordering::SeqCst)
                    && !state.shared.draining.load(Ordering::SeqCst);
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
            // Encoding refreshes the process metrics from /proc, which
            // includes listing every open descriptor: blocking work that
            // grows with the connections the proxy holds, kept off the
            // threads that serve them.
            let metrics = state.metrics.clone();
            let Ok(body) = tokio::task::spawn_blocking(move || metrics.encode()).await else {
                return Ok(text(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "metrics unavailable",
                ));
            };
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// The process has one log, started once for all the tests.
    fn log() -> Arc<Log> {
        static LOG: OnceLock<Arc<Log>> = OnceLock::new();
        LOG.get_or_init(|| Arc::new(Log::start(&Default::default()).unwrap()))
            .clone()
    }

    /// An ops server of a ready node, on a loopback port; its address.
    async fn ops_server() -> SocketAddr {
        let (addr, _, stop) = ops_server_to_hand_over().await;
        // Kept for as long as the server runs: dropping it stops serving.
        tokio::spawn(async move { stop.closed().await });
        addr
    }

    /// An ops server of a ready node, on a loopback port: its address, its
    /// state, and what tells it another process has taken its socket over.
    async fn ops_server_to_hand_over() -> (SocketAddr, Arc<OpsState>, watch::Sender<bool>) {
        let metrics = Arc::new(GfeMetrics::new());
        let shared = ProxyShared::new(
            gfe_upstream::UpstreamClient::new(1).unwrap(),
            metrics.clone(),
            Default::default(),
            Default::default(),
            Default::default(),
        );
        let state = Arc::new(OpsState {
            metrics,
            ready: Arc::new(AtomicBool::new(true)),
            shared: Arc::new(shared),
            kernel: None,
            log: log(),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = watch::channel(false);
        tokio::spawn(serve(Arc::new(listener), state.clone(), stopped));
        (addr, state, stop)
    }

    /// What the server at the other end of `stream` sends until it closes
    /// the connection, or `None` if it is still open after `wait`.
    async fn read_until_closed(stream: &mut TcpStream, wait: Duration) -> Option<String> {
        let mut received = Vec::new();
        match tokio::time::timeout(wait, stream.read_to_end(&mut received)).await {
            Ok(_) => Some(String::from_utf8_lossy(&received).to_string()),
            Err(_) => None,
        }
    }

    /// A prober whose connection the outgoing node accepted just before
    /// the handover asks it, not the successor, and the outgoing node is
    /// draining by then.
    #[tokio::test]
    async fn answers_for_the_successor_on_a_connection_accepted_before_the_handover() {
        let (addr, state, stop) = ops_server_to_hand_over().await;
        let mut prober = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        stop.send(true).unwrap();
        state.shared.draining.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(100)).await;
        prober
            .write_all(b"GET /readyz HTTP/1.1\r\nhost: t\r\n\r\n")
            .await
            .unwrap();
        let answer = read_until_closed(&mut prober, Duration::from_secs(2)).await;

        let answer = answer.unwrap_or_default().to_ascii_lowercase();
        assert!(answer.starts_with("http/1.1 200"), "{answer}");
        assert!(answer.contains("connection: close"), "{answer}");
    }

    #[tokio::test]
    async fn closes_a_connection_that_never_sends_a_request() {
        let addr = ops_server().await;
        let mut silent = TcpStream::connect(addr).await.unwrap();

        let closed = read_until_closed(&mut silent, HEADER_READ_TIMEOUT * 2).await;

        assert_eq!(closed.as_deref(), Some(""));
    }

    #[tokio::test]
    async fn closes_a_kept_connection_that_sends_no_further_request() {
        let addr = ops_server().await;
        let mut kept = TcpStream::connect(addr).await.unwrap();
        kept.write_all(b"GET /healthz HTTP/1.1\r\nhost: t\r\n\r\n")
            .await
            .unwrap();

        let closed = read_until_closed(&mut kept, HEADER_READ_TIMEOUT * 2).await;

        assert!(
            closed
                .as_deref()
                .is_some_and(|c| c.starts_with("HTTP/1.1 200")),
            "{closed:?}"
        );
    }

    #[tokio::test]
    async fn closes_a_connection_over_the_cap_at_once() {
        let addr = ops_server().await;
        let mut under_the_cap = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            under_the_cap.push(TcpStream::connect(addr).await.unwrap());
        }
        let mut over_the_cap = TcpStream::connect(addr).await.unwrap();

        over_the_cap
            .write_all(b"GET /healthz HTTP/1.1\r\nhost: t\r\n\r\n")
            .await
            .unwrap();
        let answer = read_until_closed(&mut over_the_cap, Duration::from_secs(2)).await;

        assert_eq!(answer.as_deref(), Some(""));
    }

    #[tokio::test]
    async fn serves_connections_under_the_cap() {
        let addr = ops_server().await;
        let mut others = Vec::new();
        for _ in 0..MAX_CONNECTIONS - 1 {
            others.push(TcpStream::connect(addr).await.unwrap());
        }
        let mut last = TcpStream::connect(addr).await.unwrap();

        last.write_all(b"GET /healthz HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n")
            .await
            .unwrap();
        let answer = read_until_closed(&mut last, Duration::from_secs(2)).await;

        assert!(
            answer
                .as_deref()
                .is_some_and(|a| a.starts_with("HTTP/1.1 200")),
            "{answer:?}"
        );
    }
}
