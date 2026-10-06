//! One client connection, from the accepted socket to its last byte: the
//! socket's options, the TLS handshake, registration in [`Connections`],
//! the Pingora application that serves it, and the client timeouts and the
//! drain, enforced alongside.

use crate::listener::activity::{Activity, Expiry, Verdict, verdict};
use crate::listener::conn_record::ConnRecord;
use crate::listener::stream::{ClientStream, Metered, StreamState};
use crate::listener::{ConnInfo, Connections, Shared};
use arc_swap::ArcSwap;
use gfe_config::{Listener, TimeoutsConfig};
use netkit_observability::Counter;
use netkit_tls::Acceptor;
use pingora_core::apps::ServerApp;
use pingora_core::protocols::l4::socket::SocketAddr as PingoraAddr;
use pingora_core::protocols::l4::stream::Stream as L4Stream;
use pingora_core::protocols::{GetSocketDigest, SocketDigest, Stream, TcpKeepalive};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::watch;

/// How long an HTTP/2 connection asked to leave for being idle (a `GOAWAY`)
/// may take to close before it is cut.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// How many TCP keepalive probes may go unanswered before the peer is taken
/// for gone.
const KEEPALIVE_PROBES: usize = 3;

/// How long a connection the application is done with waits for its requests
/// to be reported before it is accounted for. Pingora runs the streams of an
/// HTTP/2 connection in tasks of their own, which end a moment after the
/// connection does: without the wait, a connection that ended in order with
/// its last response is taken for one given up in the middle of a request.
/// The socket is closed by then; only the record waits.
const REQUESTS_GRACE: Duration = Duration::from_millis(500);

/// What serving a connection of the proxy's listeners needs.
pub(crate) struct Edge<A> {
    pub(crate) shared: Arc<Shared>,
    pub(crate) app: Arc<A>,
    pub(crate) tls: Acceptor,
    pub(crate) connections: Arc<Connections>,
}

/// TCP keepalive for a client connection: probe a peer that has been silent
/// for `client_idle`, every quarter of `client_idle`, and give it up after
/// [`KEEPALIVE_PROBES`] unanswered probes. A client that vanished without
/// FIN or RST then fails the connection (reason `client_unresponsive`) even
/// with an HTTP/1 request in flight, which nothing else would notice.
fn tcp_keepalive(client_idle: Duration) -> TcpKeepalive {
    // The kernel counts in whole seconds, and rejects zero.
    let second = Duration::from_secs(1);
    // Left to itself the kernel would keep probing for many minutes (nine
    // probes 75 s apart on Linux) before giving the peer up.
    TcpKeepalive {
        idle: client_idle.max(second),
        interval: (client_idle / 4).max(second),
        count: KEEPALIVE_PROBES,
        // The system's default.
        #[cfg(target_os = "linux")]
        user_timeout: Duration::ZERO,
    }
}

/// The address as the node reports it: an IPv4 client of a dual-stack
/// socket is `1.2.3.4`, not `::ffff:1.2.3.4`, as in the kernel view.
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// The accepted socket as Pingora's transport stream, without Nagle's
/// delay, and with a socket digest naming `client` and `local`: without it a
/// session has no `client_addr` / `server_addr`, and the proxy cannot find
/// the connection in [`Connections`].
fn l4_stream(tcp: TcpStream, client: SocketAddr, local: SocketAddr) -> L4Stream {
    let mut l4 = L4Stream::from(tcp);
    if let Err(e) = l4.set_nodelay() {
        tracing::debug!(error = %e, "cannot disable nagle on a client connection");
    }
    let digest = SocketDigest::from_raw_fd(l4.as_raw_fd());
    // Fresh cells: setting them cannot fail.
    let _ = digest.peer_addr.set(Some(PingoraAddr::Inet(client)));
    let _ = digest.local_addr.set(Some(PingoraAddr::Inet(local)));
    l4.set_socket_digest(digest);
    l4
}

/// Hand `stream` to `app` until the app is done with it. An app may hand a
/// connection back (`Some`) to be processed again.
async fn run_app<A>(app: &Arc<A>, stream: Stream, shutdown: &watch::Receiver<bool>)
where
    A: ServerApp + Send + Sync + 'static,
{
    let mut next = app.process_new(stream, shutdown).await;
    while let Some(stream) = next {
        next = app.process_new(stream, shutdown).await;
    }
}

/// Wait, for at most [`REQUESTS_GRACE`], until no request of `conn` is in
/// flight.
async fn requests_reported(conn: &ConnInfo) {
    let reported = async {
        // A wake-up may be left over from a request that ended earlier:
        // look again after each one.
        while conn.has_request_in_flight() {
            conn.went_idle().await;
        }
    };
    let _ = tokio::time::timeout(REQUESTS_GRACE, reported).await;
}

/// Serve one connection accepted from `peer` on `listener` (as configured
/// now) until it ends. `shutdown` is the node's drain signal.
///
/// The connection is accounted for by a [`ConnRecord`], which reports it
/// when this future completes or is dropped. It is findable in the edge's
/// [`Connections`] from before the application sees it until then.
pub(crate) async fn serve<A>(
    edge: &Edge<A>,
    tcp: TcpStream,
    peer: SocketAddr,
    listener: Arc<ArcSwap<Listener>>,
    shutdown: watch::Receiver<bool>,
) where
    A: ServerApp + Send + Sync + 'static,
{
    let local = match tcp.local_addr() {
        Ok(local) => canonical(local),
        // The socket is already gone.
        Err(e) => {
            tracing::debug!(error = %e, "accepted a connection without a local address");
            return;
        }
    };
    let client = canonical(peer);
    let shared = &edge.shared;
    let accepted_on = listener.load_full();
    let mut record = ConnRecord::open(Arc::clone(shared), &accepted_on, local, client);

    let mut l4 = l4_stream(tcp, client, local);
    if let Err(e) = l4.set_keepalive(&tcp_keepalive(shared.timeouts().client_idle)) {
        tracing::debug!(error = %e, "cannot enable tcp keepalive on a client connection");
    }
    let wire = record.meter(l4);

    let (stream, tls) = if accepted_on.is_tls() {
        let started = Instant::now();
        let handshake =
            tokio::time::timeout(shared.timeouts().tls_handshake, edge.tls.accept(wire)).await;
        shared.export_sni_misses();
        match handshake {
            Ok(Ok((stream, tls))) => {
                record.tls_established(&tls, started.elapsed());
                (ClientStream::tls(stream, &tls), Some(tls))
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
        (ClientStream::plain(wire), None)
    };

    let conn = ConnInfo::new(client, local, listener, tls);
    let _registration = edge.connections.register(Arc::clone(&conn));
    record.serving(Arc::clone(&conn));

    // The application's own shutdown signal, so that the edge can ask one
    // connection to leave (an HTTP/2 `GOAWAY`) without draining the node.
    let (leave_tx, leave) = watch::channel(*shutdown.borrow());
    let stream_state = Arc::clone(record.stream());
    tokio::select! {
        () = async {
            run_app(&edge.app, Box::new(stream), &leave).await;
            requests_reported(&conn).await;
        } => record.served(),
        never = watchdog(&conn, &stream_state, shared.timeouts(), shutdown, &leave_tx) => {
            match never {}
        }
    }
}

/// Serve a connection with `app` and nothing else: no accounting, no
/// registration, no client timeouts beyond the app's own. For the node's
/// own small endpoints.
pub(crate) async fn serve_unaccounted<A>(
    app: &Arc<A>,
    tcp: TcpStream,
    peer: SocketAddr,
    shutdown: &watch::Receiver<bool>,
) where
    A: ServerApp + Send + Sync + 'static,
{
    let Ok(local) = tcp.local_addr() else {
        return;
    };
    let l4 = l4_stream(tcp, canonical(peer), canonical(local));
    let wire = Metered::new(
        l4,
        Arc::new(StreamState::default()),
        Counter::default(),
        Counter::default(),
    );
    run_app(app, Box::new(ClientStream::plain(wire)), shutdown).await;
}

/// End the connection for `expiry`, then wait for the application to notice.
async fn end(stream: &StreamState, expiry: Expiry) -> Infallible {
    stream.cut(expiry);
    std::future::pending().await
}

/// Enforce the client timeouts and the drain on one connection, for as long
/// as it is served (this future never completes; it is dropped with the
/// connection).
///
/// - `request_header`: the first request head must arrive within this long
///   of the connection being established, else the connection is cut.
/// - `client_idle`: a connection with no request in flight for this long is
///   ended. An HTTP/1 connection is waiting for a request head, and is cut;
///   an HTTP/2 one is asked to leave (`GOAWAY`), and cut after
///   [`CLOSE_GRACE`] if it has not.
/// - drain: once `shutdown` turns `true`, the application is told (`leave`),
///   which makes it send `GOAWAY` on HTTP/2 and `Connection: close` with the
///   next HTTP/1 response. A connection with no request in flight is given
///   half the drain deadline to send one more, because cutting it at once
///   would race with a request already on its way; it is cut then.
///
/// A connection with a request in flight is never cut by any of these.
async fn watchdog(
    conn: &ConnInfo,
    stream: &StreamState,
    timeouts: &TimeoutsConfig,
    mut shutdown: watch::Receiver<bool>,
    leave: &watch::Sender<bool>,
) -> Infallible {
    // Once draining: until when one more request is waited for.
    let mut leave_by: Option<Instant> = None;
    // Once an idle HTTP/2 connection has been asked to leave: until when it
    // may take to.
    let mut asked_until: Option<Instant> = None;
    loop {
        let now = Instant::now();
        let wake_at = match verdict(Activity::of(conn), now, timeouts, leave_by) {
            Verdict::Expired(Expiry::Idle) if stream.is_h2() => match asked_until {
                None => {
                    stream.ask_to_leave(Expiry::Idle);
                    leave.send_replace(true);
                    let until = now + CLOSE_GRACE;
                    asked_until = Some(until);
                    Some(until)
                }
                Some(until) if now < until => Some(until),
                Some(_) => return end(stream, Expiry::Idle).await,
            },
            Verdict::Expired(expiry) => return end(stream, expiry).await,
            Verdict::CheckAgainAt(at) => Some(at),
            Verdict::WaitUntilIdle => None,
        };
        let sleep = tokio::time::sleep_until(wake_at.unwrap_or(now).into());
        tokio::select! {
            () = sleep, if wake_at.is_some() => {}
            // Also while waiting for a deadline: a request may have come
            // and gone since, which moves the deadline.
            () = conn.went_idle() => {}
            // The sender going away means the node is going away, too.
            _ = shutdown.wait_for(|draining| *draining), if leave_by.is_none() => {
                leave.send_replace(true);
                leave_by = Some(Instant::now() + timeouts.drain_deadline / 2);
            }
        }
    }
}

#[cfg(test)]
#[path = "connection_test.rs"]
mod tests;
