//! One client connection, from the accepted socket to its last byte: the
//! socket's options, the TLS handshake under its timeout, HTTP until the
//! connection ends, and the record that accounts for it.
//!
//! The HTTP side (the protocols, the client timeouts once the connection is
//! established, the drain) is `netkit_http::server::serve`'s. What is GFE's
//! here is which of the node's settings it is held to, what a request is
//! told about its connection, and how the connection is accounted for.

use crate::edge::conn_record::ConnRecord;
use crate::edge::{ConnInfo, RequestHandler, Shared};
use crate::metrics::RejectLabel;
use gfe_config::{LimitsConfig, Listener, TimeoutsConfig};
use netkit_http::body::{BoxBody, Incoming};
use netkit_http::server::{self, Closed, InvalidOptions, Options};
use netkit_http::{Request, Response};
use netkit_listen::{Accepted, Limit, Serve};
use netkit_tls::Acceptor;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::watch;

/// How many TCP keepalive probes may go unanswered before the peer is taken
/// for gone.
const KEEPALIVE_PROBES: u32 = 3;

/// The TCP keepalive a client connection is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcpKeepalive {
    idle: Duration,
    interval: Duration,
    probes: u32,
}

/// TCP keepalive for a client connection: probe a peer that has been silent
/// for `client_idle`, every quarter of `client_idle`, and give it up after
/// [`KEEPALIVE_PROBES`] unanswered probes. A client that vanished without
/// FIN or RST then fails the connection (`client_unresponsive`) even with
/// an HTTP/1.1 request in flight, which nothing else would notice.
fn tcp_keepalive(client_idle: Duration) -> TcpKeepalive {
    // The kernel counts in whole seconds, and rejects zero.
    let second = Duration::from_secs(1);
    // Left to itself the kernel would keep probing for many minutes (nine
    // probes 75 s apart on Linux) before giving the peer up.
    TcpKeepalive {
        idle: client_idle.max(second),
        interval: (client_idle / 4).max(second),
        probes: KEEPALIVE_PROBES,
    }
}

/// What HTTP on a client connection is held to, from the node's settings:
///
/// - the first request head must be complete within `request_header`;
/// - with no request in flight for `client_idle` the connection is shut
///   down, and an HTTP/2 client silent for that long is sent a PING, which
///   it has a quarter of `client_idle` to acknowledge;
/// - once draining, a connection with no request in flight is given half
///   the drain deadline to send one more, which leaves the other half for
///   that request to be answered.
fn http_options(timeouts: &TimeoutsConfig, limits: &LimitsConfig) -> Options {
    Options {
        header_timeout: timeouts.request_header,
        idle_timeout: timeouts.client_idle,
        keep_alive_timeout: timeouts.client_idle / 4,
        drain_idle_grace: timeouts.drain_deadline / 2,
        max_header_bytes: limits.max_header_bytes,
        max_concurrent_streams: limits.max_h2_concurrent_streams,
    }
}

/// Serves the client connections of the node's listeners: what
/// `netkit_listen` hands every connection it accepts to.
///
/// A connection accepted on an HTTPS listener (as the listener is
/// configured when the connection is accepted) terminates TLS with one
/// acceptor shared by all of them; its requests are answered by `H`.
pub struct Edge<H> {
    shared: Arc<Shared>,
    handler: Arc<H>,
    tls: Acceptor,
    http: Options,
}

impl<H: RequestHandler> Edge<H> {
    /// An edge whose connections share `shared`, terminate TLS with `tls`
    /// on HTTPS listeners, and are answered by `handler`.
    ///
    /// Fails if the timeouts and limits of `shared` cannot be served with
    /// (a `max_header_bytes` below what HTTP needs, a timeout that rounds
    /// to zero), rather than closing every connection later.
    pub fn new(
        shared: Arc<Shared>,
        handler: Arc<H>,
        tls: Acceptor,
    ) -> Result<Self, InvalidOptions> {
        let http = http_options(shared.timeouts(), shared.limits());
        http.validate()?;
        Ok(Edge {
            shared,
            handler,
            tls,
            http,
        })
    }

    /// What its connections share.
    pub fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    /// Serve one accepted connection until it ends. The record accounts
    /// for it when this future completes or is dropped.
    async fn serve_connection(&self, accepted: Accepted<Listener>) {
        let Accepted {
            stream,
            peer,
            local,
            listener,
            drain,
        } = accepted;
        let accepted_on = listener.load_full();
        let mut record = ConnRecord::open(Arc::clone(&self.shared), &accepted_on, local, peer);
        set_socket_options(&stream, self.shared.timeouts());
        let wire = record.meter(stream);

        let closed = if accepted_on.is_tls() {
            let started = Instant::now();
            let handshake =
                tokio::time::timeout(self.shared.timeouts().tls_handshake, self.tls.accept(wire))
                    .await;
            self.shared.export_sni_misses();
            match handshake {
                Ok(Ok((stream, tls))) => {
                    record.tls_established(&tls, started.elapsed());
                    let conn = ConnInfo::new(peer, local, listener, Some(tls));
                    self.serve_http(CloseNotify(stream), conn, drain).await
                }
                Ok(Err(e)) => {
                    tracing::debug!(error = %e, "tls handshake failed");
                    record.tls_failed(&e);
                    return;
                }
                Err(_) => {
                    record.tls_timed_out();
                    return;
                }
            }
        } else {
            let conn = ConnInfo::new(peer, local, listener, None);
            self.serve_http(wire, conn, drain).await
        };
        record.closed(&closed);
    }

    /// Serve HTTP on `io`, the established connection `conn`, until it
    /// ends.
    async fn serve_http<S>(&self, io: S, conn: ConnInfo, drain: watch::Receiver<bool>) -> Closed
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let handler = Arc::new(OnConnection {
            conn: Arc::new(conn),
            handler: Arc::clone(&self.handler),
        });
        server::serve(io, handler, self.http, drain).await
    }
}

impl<H: RequestHandler> Serve<Listener> for Edge<H> {
    fn serve(&self, accepted: Accepted<Listener>) -> impl Future<Output = ()> + Send {
        self.serve_connection(accepted)
    }

    /// Counted as `gfe_connections_rejected_total`: `reason="client_rate"`
    /// for a client over `client_connections_per_second`, `reason="limit"`
    /// for either connection limit.
    fn refused(&self, _listener: &Listener, limit: Limit) {
        let reason = match limit {
            Limit::ConnectionsPerPeer => "client_rate",
            Limit::MaxConnections | Limit::MaxConnectionsPerListener => "limit",
        };
        self.shared
            .metrics()
            .proxy
            .connections_rejected
            .get_or_create(&RejectLabel {
                reason: reason.into(),
            })
            .inc();
    }
}

impl<H> std::fmt::Debug for Edge<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Edge")
            .field("shared", &self.shared)
            .field("http", &self.http)
            .finish_non_exhaustive()
    }
}

/// Disable Nagle's delay and enable TCP keepalive on an accepted socket. A
/// socket that refuses either is served without it.
fn set_socket_options(stream: &TcpStream, timeouts: &TimeoutsConfig) {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(error = %e, "cannot disable nagle on a client connection");
    }
    let keepalive = tcp_keepalive(timeouts.client_idle);
    if let Err(e) =
        netkit_listen::keep_alive(stream, keepalive.idle, keepalive.interval, keepalive.probes)
    {
        tracing::debug!(error = %e, "cannot enable tcp keepalive on a client connection");
    }
}

/// A TLS stream that tells its client the node is closing (`close_notify`)
/// when it is dropped without having been shut down: what happens to a
/// connection HTTP gives up on (a request head that never came) and to one
/// cut at the drain deadline.
///
/// Without it the client cannot tell an orderly end from a connection cut
/// short, and one that waits for the answer to its own `close_notify`
/// reports an error. One attempt, without waiting: a socket whose buffer is
/// full (the client is not reading) is closed without the goodbye. A stream
/// already shut down sends nothing more.
struct CloseNotify<S: AsyncWrite + Unpin>(S);

impl<S: AsyncWrite + Unpin> Drop for CloseNotify<S> {
    fn drop(&mut self) {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let _ = Pin::new(&mut self.0).poll_shutdown(&mut cx);
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for CloseNotify<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CloseNotify<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// The handler of one connection's requests: `handler`, told each time
/// which connection the request arrived on.
struct OnConnection<H> {
    conn: Arc<ConnInfo>,
    handler: Arc<H>,
}

impl<H: RequestHandler> server::Handler for OnConnection<H> {
    fn handle(&self, request: Request<Incoming>) -> impl Future<Output = Response<BoxBody>> + Send {
        self.handler.handle(Arc::clone(&self.conn), request)
    }
}

#[cfg(test)]
#[path = "connection_test.rs"]
mod tests;
