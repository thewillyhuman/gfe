//! The node's own endpoints: `/healthz`, `/readyz` and `/metrics`.
//!
//! Served on a socket of their own by `netkit-listen`'s `serve_plain`, one
//! cap and nothing else, with `netkit-http` speaking HTTP/1.1 or HTTP/2
//! (prior knowledge) on each connection: they must keep answering while the
//! proxy drains, and must not show up as client traffic, so nothing here
//! goes through the proxy's listeners, logs or metrics. Any method is
//! answered as `GET` is; any other path is `404`.
//!
//! The socket stops being served when another process takes it over: the
//! connections already open are then drained the way `netkit-http` drains
//! a connection, so that a client that keeps one asks the new process
//! next.

use gfe_proxy::Frontend;
use gfe_proxy::metrics::{GfeMetrics, LogDestinationLabel};
use netkit_http::body::{self, BoxBody, Incoming};
use netkit_http::server::{self, Handler, Options};
use netkit_http::{Bytes, HeaderValue, Request, Response, StatusCode, header};
use netkit_listen::{Accepted, Limit, Serve};
use netkit_observability::{Log, without_histogram_metadata};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;

/// How many connections the endpoint serves at once. Probes and scrapes
/// need a handful; the node's file descriptors are for the proxy. A
/// connection over the cap is closed at once.
const MAX_CONNECTIONS: usize = 64;

/// How long a client has to send a request head, and how long a connection
/// it keeps may wait idle for the next one.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// What each connection is held to.
const CONNECTION_OPTIONS: Options = Options {
    // A prober or scraper sends its head at once; one that does not is
    // stalled, and gives its slot back.
    header_timeout: HEADER_READ_TIMEOUT,
    // A scraper that keeps its connection between scrapes is served as long
    // as it asks often enough; an idle one gives its slot back.
    idle_timeout: HEADER_READ_TIMEOUT,
    // An HTTP/2 client that does not acknowledge a PING within as long as
    // any client has to send a head is gone.
    keep_alive_timeout: HEADER_READ_TIMEOUT,
    // After a handover, a request already on its way on a connection
    // accepted here is still answered; a second is long enough for that on
    // the networks probes come from, and keeps the old process from
    // lingering.
    drain_idle_grace: Duration::from_secs(1),
    // Probe and scrape heads are a few hundred bytes: the smallest buffer
    // the server can work with is plenty.
    max_header_bytes: server::MIN_HEADER_BYTES,
    // One scrape or probe at a time is what clients do; a few streams let
    // one ask for the three paths at once without letting a connection run
    // many encodings of the metrics in parallel.
    max_concurrent_streams: 4,
};

/// What `/metrics` is served as.
const OPENMETRICS: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// How `/metrics` exposes the histograms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Histograms {
    /// Declared as histograms, which is the format's own way.
    Typed,
    /// Without their family metadata, as series of no declared type: what
    /// `/metrics?histograms=untyped` asks for.
    Untyped,
}

impl Histograms {
    /// What the query string of a scrape asks for. Parameters other than
    /// `histograms` are not this server's and are ignored. A value it does
    /// not know is returned as the error: a scraper with a typo in its
    /// configuration is told, not served the default.
    fn asked_by(query: Option<&str>) -> Result<Self, String> {
        let value = query
            .unwrap_or_default()
            .split('&')
            .find_map(|parameter| parameter.strip_prefix("histograms="));
        match value {
            None => Ok(Self::Typed),
            Some("untyped") => Ok(Self::Untyped),
            Some(unknown) => Err(unknown.to_string()),
        }
    }
}

/// The ops endpoints of a node: what they answer from.
pub(crate) struct Ops {
    metrics: Arc<GfeMetrics>,
    /// The node's log, for what it has lost.
    log: Arc<Log>,
    /// The proxy, once it serves. Until then the node is not ready.
    frontend: OnceLock<Arc<Frontend>>,
}

impl Ops {
    /// The endpoints of a node that does not serve yet: `/readyz` fails
    /// until [`Ops::serving`].
    pub(crate) fn new(metrics: Arc<GfeMetrics>, log: Arc<Log>) -> Ops {
        Ops {
            metrics,
            log,
            frontend: OnceLock::new(),
        }
    }

    /// The node serves with `frontend`: it is ready until that drains.
    pub(crate) fn serving(&self, frontend: Arc<Frontend>) {
        if self.frontend.set(frontend).is_err() {
            tracing::warn!("the ops endpoints were told twice that the node serves");
        }
    }

    /// Whether `/readyz` says ready. `handed_over` is whether another
    /// process has taken the ops socket over, which it does only once it is
    /// ready: the address is then ready whatever this process is doing.
    fn is_ready(&self, handed_over: bool) -> bool {
        handed_over
            || self
                .frontend
                .get()
                .is_some_and(|frontend| !frontend.is_draining())
    }

    /// The answer to a request for `path` with `query`.
    async fn answer(&self, path: &str, query: Option<&str>, handed_over: bool) -> Answer {
        match path {
            "/healthz" => Answer::text(StatusCode::OK, "ok"),
            "/readyz" if self.is_ready(handed_over) => Answer::text(StatusCode::OK, "ready"),
            "/readyz" => Answer::text(StatusCode::SERVICE_UNAVAILABLE, "not ready"),
            "/metrics" => match Histograms::asked_by(query) {
                Ok(histograms) => self.metrics(histograms).await,
                Err(unknown) => Answer::text(
                    StatusCode::BAD_REQUEST,
                    &format!("unknown value for histograms: {unknown} (known: untyped)"),
                ),
            },
            _ => Answer::text(StatusCode::NOT_FOUND, "not found"),
        }
    }

    /// The exposition, with the metrics that are sampled rather than counted
    /// brought up to date first.
    async fn metrics(&self, histograms: Histograms) -> Answer {
        let runtime = tokio::runtime::Handle::current().metrics();
        let process = &self.metrics.process;
        process.runtime_workers.set(gauge(runtime.num_workers()));
        process
            .runtime_alive_tasks
            .set(gauge(runtime.num_alive_tasks()));
        process
            .runtime_global_queue_depth
            .set(gauge(runtime.global_queue_depth()));
        for (destination, lost) in self.log.lost_lines() {
            process
                .log_lost_lines
                .get_or_create(&LogDestinationLabel {
                    destination: destination.to_string(),
                })
                .set(i64::try_from(lost).unwrap_or(i64::MAX));
        }
        if let Some(frontend) = self.frontend.get() {
            frontend.refresh_metrics();
        }
        // Encoding refreshes the process metrics from /proc, which includes
        // listing every open descriptor: blocking work that grows with the
        // connections the proxy holds, kept off the threads that serve them.
        let metrics = Arc::clone(&self.metrics);
        let encode = move || match histograms {
            Histograms::Typed => metrics.encode(),
            Histograms::Untyped => without_histogram_metadata(&metrics.encode()),
        };
        match tokio::task::spawn_blocking(encode).await {
            Ok(body) => Answer {
                status: StatusCode::OK,
                content_type: Some(OPENMETRICS),
                body: Bytes::from(body),
            },
            Err(_) => Answer::text(StatusCode::INTERNAL_SERVER_ERROR, "metrics unavailable"),
        }
    }
}

/// A count as a gauge's value.
fn gauge(count: usize) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
}

/// What a request is answered with.
struct Answer {
    status: StatusCode,
    content_type: Option<&'static str>,
    body: Bytes,
}

impl Answer {
    /// A one-line answer.
    fn text(status: StatusCode, body: &str) -> Answer {
        Answer {
            status,
            content_type: None,
            body: Bytes::from(format!("{body}\n")),
        }
    }

    /// The answer as a response; its length is the body's.
    fn into_response(self) -> Response<BoxBody> {
        let mut response = Response::new(body::full(self.body));
        *response.status_mut() = self.status;
        if let Some(content_type) = self.content_type {
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        }
        response
    }
}

/// What the accept loop hands each connection to.
struct Endpoint {
    ops: Arc<Ops>,
}

impl Serve<()> for Endpoint {
    /// Serve the connection until it ends. It is drained once the socket
    /// has been handed over, which is the signal the accept loop stops on.
    async fn serve(&self, accepted: Accepted<()>) {
        let exchange = Arc::new(Exchange {
            ops: Arc::clone(&self.ops),
            handed_over: accepted.drain.clone(),
        });
        let closed = server::serve(
            accepted.stream,
            exchange,
            CONNECTION_OPTIONS,
            accepted.drain,
        )
        .await;
        tracing::debug!(
            peer = %accepted.peer,
            reason = ?closed.reason,
            error = closed.error.as_deref().unwrap_or_default(),
            "ops connection closed"
        );
    }

    fn refused(&self, _: &(), _: Limit) {
        tracing::debug!("ops connection over the cap closed");
    }
}

/// The requests of one connection, answered by the endpoints.
struct Exchange {
    ops: Arc<Ops>,
    /// Turns `true` once another process has taken the socket over.
    handed_over: watch::Receiver<bool>,
}

impl Handler for Exchange {
    async fn handle(&self, request: Request<Incoming>) -> Response<BoxBody> {
        let handed_over = *self.handed_over.borrow();
        let uri = request.uri();
        self.ops
            .answer(uri.path(), uri.query(), handed_over)
            .await
            .into_response()
    }
}

/// The socket the ops endpoints listen on.
///
/// `inherited` is a socket that already listens, with the address it is
/// configured on: it is used instead of binding one if that address is
/// `addr`, and closed otherwise.
pub(crate) async fn listen(
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

/// Serve the ops endpoints on `socket` until `handed_over` turns `true`,
/// which is when another process has taken the socket over (or until its
/// sender is dropped). Connections already accepted are then drained: a
/// request already on its way is still answered, `/readyz` as ready, with
/// `Connection: close` on HTTP/1.1, and the connection closed, so that a
/// client that keeps one asks the new process next. The socket itself is
/// left open.
pub(crate) async fn serve(
    socket: Arc<TcpListener>,
    ops: Arc<Ops>,
    handed_over: watch::Receiver<bool>,
) {
    let endpoint = Arc::new(Endpoint { ops });
    netkit_listen::serve_plain(socket, (), endpoint, MAX_CONNECTIONS, handed_over).await;
}

#[cfg(test)]
#[path = "ops_test.rs"]
mod tests;
