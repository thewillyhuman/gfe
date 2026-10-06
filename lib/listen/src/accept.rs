//! Accept loops: one per listening socket, enforcing the connection limits,
//! each accepted connection served in a task of its own so that nothing
//! slows the loop down.
//!
//! What is done with a connection is the caller's ([`Serve`]): this module
//! does not read from it, write to it, time it out or account for it. It
//! only decides whether the connection may be served at all, and when the
//! serving is over.

use arc_swap::ArcSwap;
use netkit_rate_limiting::{ConcurrencyLimit, Permit};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// How long an accept loop waits after a failed `accept` before trying
/// again. The errors that persist (out of file descriptors or memory) would
/// otherwise spin the loop on a core and flood the log.
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(100);

/// How many connections may be open at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Over all the listeners of a set.
    pub max_connections: usize,
    /// On any one listener.
    pub max_connections_per_listener: usize,
}

/// Which of the [`Limits`] a refused connection ran into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// [`Limits::max_connections`]. Checked first: a connection over both
    /// limits is reported under this one.
    MaxConnections,
    /// [`Limits::max_connections_per_listener`].
    MaxConnectionsPerListener,
}

/// What is done with the connections a listener accepts. `T` is what the
/// caller attached to the listener.
pub trait Serve<T>: Send + Sync + 'static {
    /// Serve one accepted connection until it ends. The future is dropped if
    /// the connection is still open when a drain's deadline has passed, so
    /// what must happen however the connection ends belongs in a `Drop`.
    fn serve(&self, accepted: Accepted<T>) -> impl Future<Output = ()> + Send;

    /// A connection on `listener` was closed as soon as it was accepted,
    /// because `limit` was reached. Called on the accept loop: it must not
    /// block.
    fn refused(&self, listener: &T, limit: Limit);
}

/// A connection that was accepted, and what it was accepted on.
#[derive(Debug)]
pub struct Accepted<T> {
    /// The connection itself.
    pub stream: TcpStream,
    /// The client's address.
    pub peer: SocketAddr,
    /// The address the client connected to: the listener's, or, on a
    /// wildcard listener, the one of the host's addresses it picked.
    pub local: SocketAddr,
    /// What the caller attached to the listener, as it is now: a reconcile
    /// can replace it while the socket, and this connection, stay. Load it
    /// when it is needed rather than once.
    pub listener: Arc<ArcSwap<T>>,
    /// Turns `true` when the process drains: the connection should then ask
    /// its client to leave, and end as soon as it can.
    pub drain: watch::Receiver<bool>,
}

/// The connections a set of listeners has open, capped across all of them
/// (`max_connections`).
#[derive(Debug)]
pub(crate) struct OpenConnections {
    limit: Arc<ConcurrencyLimit>,
}

impl OpenConnections {
    pub(crate) fn new(max: usize) -> Arc<Self> {
        Arc::new(OpenConnections {
            limit: ConcurrencyLimit::new(Some(max)),
        })
    }
}

/// A connection's place under both caps, given back when the connection's
/// task ends, however it ends.
struct Slot {
    _permits: (Permit, Permit),
}

/// Resolves when `cut` turns `true`; never if its sender goes away.
async fn cut_signalled(cut: &mut watch::Receiver<bool>) {
    if cut.wait_for(|cut| *cut).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Accept connections on `socket` until `drain` turns `true` (or its sender
/// goes away), and hand each to `serve`, in a task of its own. The
/// connections accepted until then watch the same signal, to leave in an
/// orderly way, and are dropped when `cut` turns `true`.
///
/// `listener` is what the caller attached to the socket, read anew for
/// every connection, so that it can change while the socket stays bound.
///
/// `open` bounds the connections open across all listeners; a limit of its
/// own bounds this listener's (`max_per_listener`). When either is reached
/// the connection is closed at once and reported to `serve`.
///
/// The loop only ever waits in `accept` or in the pause after an accept
/// error, so aborting its task closes the socket without dropping an
/// accepted connection.
pub(crate) async fn run_listener<T, S>(
    serve: Arc<S>,
    listener: Arc<ArcSwap<T>>,
    socket: Arc<TcpListener>,
    open: Arc<OpenConnections>,
    max_per_listener: usize,
    mut drain: watch::Receiver<bool>,
    cut: watch::Receiver<bool>,
) where
    T: Send + Sync + 'static,
    S: Serve<T>,
{
    let bound = socket.local_addr();
    let on_this_listener = ConcurrencyLimit::new(Some(max_per_listener));
    loop {
        let accepted = tokio::select! {
            _ = drain.wait_for(|draining| *draining) => break,
            accepted = socket.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, addr = ?bound, "accept error");
                if pause_unless_drained(&mut drain, ACCEPT_ERROR_PAUSE).await {
                    break;
                }
                continue;
            }
        };

        let permits = match open.limit.try_acquire() {
            Err(_) => Err(Limit::MaxConnections),
            Ok(total) => match on_this_listener.try_acquire() {
                Err(_) => Err(Limit::MaxConnectionsPerListener),
                Ok(here) => Ok((total, here)),
            },
        };
        let permits = match permits {
            Ok(permits) => permits,
            Err(limit) => {
                tracing::debug!(%peer, ?limit, "connection over a limit, closed");
                // Closed before it is reported: the report runs the caller's
                // code, which should not hold the connection up.
                drop(stream);
                serve.refused(&listener.load(), limit);
                continue;
            }
        };
        let slot = Slot { _permits: permits };

        let local = stream
            .local_addr()
            .or_else(|_| socket.local_addr())
            .unwrap_or(peer);
        let accepted = Accepted {
            stream,
            peer,
            local,
            listener: Arc::clone(&listener),
            drain: drain.clone(),
        };
        let serve = Arc::clone(&serve);
        let mut cut = cut.clone();
        tokio::spawn(async move {
            // Dropped last: the connection is over before its place is
            // given back.
            let _slot = slot;
            tokio::select! {
                () = serve.serve(accepted) => {}
                () = cut_signalled(&mut cut) => {}
            }
        });
    }
    tracing::debug!(addr = ?bound, "draining, stopped accepting");
}

/// Serve `socket` with `serve`, at most `max_connections` at once, until
/// `drain` turns `true` (usually a [`Drain`](crate::Drain)'s subscriber):
/// this then returns, and the connections still open are left to finish
/// (they see `drain` too). `listener` is what the connections are told they
/// were accepted on.
///
/// One socket and one cap, nothing else: no reconcile, no handover, no cut
/// at a deadline. It is for a process's own small endpoints (health,
/// metrics), which have to keep answering while the rest of the process
/// drains, and so are given a signal of their own. A connection over the
/// cap is refused with [`Limit::MaxConnections`].
pub async fn serve_plain<T, S>(
    socket: Arc<TcpListener>,
    listener: T,
    serve: Arc<S>,
    max_connections: usize,
    drain: watch::Receiver<bool>,
) where
    T: Send + Sync + 'static,
    S: Serve<T>,
{
    // A cut that is never sent: nothing here waits for the connections.
    let (_, never_cut) = watch::channel(false);
    run_listener(
        serve,
        Arc::new(ArcSwap::from_pointee(listener)),
        socket,
        OpenConnections::new(max_connections),
        max_connections,
        drain,
        never_cut,
    )
    .await;
}

/// Wait for `pause`, unless `drain` turns `true` (or its sender goes away)
/// first. Returns `true` if the pause was cut short by the drain.
async fn pause_unless_drained(drain: &mut watch::Receiver<bool>, pause: Duration) -> bool {
    tokio::select! {
        () = tokio::time::sleep(pause) => false,
        _ = drain.wait_for(|draining| *draining) => true,
    }
}

#[cfg(test)]
#[path = "accept_test.rs"]
mod tests;
