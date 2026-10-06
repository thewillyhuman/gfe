//! The node's own endpoints: `/healthz`, `/readyz` and `/metrics`.
//!
//! A small Pingora application, served by the edge's
//! [`serve_plain`](gfe_core::listener::serve_plain) on a socket of its own:
//! it must keep answering while the proxy drains, and must not show up as
//! client traffic. It speaks HTTP/1.1, and drives its sessions itself
//! rather than through Pingora's `HttpServerApp`, which waits a minute for a
//! request head: here a client has [`HEADER_READ_TIMEOUT`].

use async_trait::async_trait;
use bytes::Bytes;
use gfe_core::Frontend;
use netkit_observability::{GfeMetrics, Log, LogDestinationLabel, without_histogram_metadata};
use pingora_core::apps::ServerApp;
use pingora_core::protocols::Stream;
use pingora_core::protocols::http::ServerSession;
use pingora_core::server::ShutdownWatch;
use pingora_http::ResponseHeader;
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
            "/healthz" => Answer::text(200, "ok"),
            "/readyz" if self.is_ready(handed_over) => Answer::text(200, "ready"),
            "/readyz" => Answer::text(503, "not ready"),
            "/metrics" => match Histograms::asked_by(query) {
                Ok(histograms) => self.metrics(histograms).await,
                Err(unknown) => Answer::text(
                    400,
                    &format!("unknown value for histograms: {unknown} (known: untyped)"),
                ),
            },
            _ => Answer::text(404, "not found"),
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
                status: 200,
                content_type: Some(OPENMETRICS),
                body: Bytes::from(body),
            },
            Err(_) => Answer::text(500, "metrics unavailable"),
        }
    }

    /// Answer the request whose head `session` has read. On HTTP/1.1 the
    /// connection is kept for the next one, unless the client says
    /// otherwise or the socket has been `handed_over`: a client that keeps
    /// its connection then asks the process that serves now with its next
    /// request.
    async fn respond(
        &self,
        session: &mut ServerSession,
        handed_over: bool,
    ) -> pingora_core::Result<()> {
        let uri = &session.req_header().uri;
        let answer = self.answer(uri.path(), uri.query(), handed_over).await;
        let keepalive = (!handed_over).then_some(HEADER_READ_TIMEOUT.as_secs());
        session.set_keepalive(keepalive);
        let mut head = ResponseHeader::build(answer.status, Some(2))?;
        head.set_content_length(answer.body.len())?;
        if let Some(content_type) = answer.content_type {
            head.insert_header("content-type", content_type)?;
        }
        session.write_response_header(Box::new(head)).await?;
        session.write_response_body(answer.body, true).await
    }
}

/// A count as a gauge's value.
fn gauge(count: usize) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
}

/// What a request is answered with.
struct Answer {
    status: u16,
    content_type: Option<&'static str>,
    body: Bytes,
}

impl Answer {
    /// A one-line answer.
    fn text(status: u16, body: &str) -> Answer {
        Answer {
            status,
            content_type: None,
            body: Bytes::from(format!("{body}\n")),
        }
    }
}

#[async_trait]
impl ServerApp for Ops {
    /// Serve the requests of one connection, one after the other, until the
    /// client closes it, keeps it idle for [`HEADER_READ_TIMEOUT`], or is
    /// told to close it. `handed_over` turns `true` once another process has
    /// taken the socket over: a connection already answered here is then
    /// closed while it waits for its next request, and one not answered yet
    /// is answered once more and closed with the answer, since closing it
    /// at once could close it on a request already on its way.
    async fn process_new(
        self: &Arc<Self>,
        stream: Stream,
        handed_over: &ShutdownWatch,
    ) -> Option<Stream> {
        let mut stream = stream;
        let mut answered = false;
        loop {
            let mut session = ServerSession::new_http1(stream);
            if !next_request(&mut session, handed_over.clone(), answered).await {
                return None;
            }
            let now_handed_over = *handed_over.borrow();
            if let Err(e) = self.respond(&mut session, now_handed_over).await {
                tracing::debug!(error = %e, "ops request not answered");
                return None;
            }
            stream = session.finish().await.ok()??.into_parts().0;
            answered = true;
        }
    }
}

/// Wait for the head of the next request on `session`; whether one came.
/// None did if the client closed the connection or sent a head that is not
/// one, if [`HEADER_READ_TIMEOUT`] went by first, or if the connection has
/// been `answered` before and the socket is `handed_over`.
async fn next_request(
    session: &mut ServerSession,
    mut handed_over: watch::Receiver<bool>,
    answered: bool,
) -> bool {
    tokio::select! {
        read = tokio::time::timeout(HEADER_READ_TIMEOUT, session.read_request()) => {
            matches!(read, Ok(Ok(true)))
        }
        _ = handed_over.wait_for(|handed_over| *handed_over), if answered => false,
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
/// which is when another process has taken the socket over. Connections
/// already accepted are still answered, `/readyz` as ready, and then
/// closed, so that a client that keeps one asks the new process next.
pub(crate) async fn serve(
    socket: Arc<TcpListener>,
    ops: Arc<Ops>,
    handed_over: watch::Receiver<bool>,
) {
    gfe_core::listener::serve_plain(&socket, ops, MAX_CONNECTIONS, handed_over).await;
}

#[cfg(test)]
#[path = "ops_test.rs"]
mod tests;
