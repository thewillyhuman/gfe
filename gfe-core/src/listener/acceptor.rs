//! Accept loops: one per listening socket, enforcing the connection limits,
//! each accepted connection served in a task of its own so that nothing
//! slows the loop down.

use crate::listener::connection::{self, Edge};
use arc_swap::ArcSwap;
use gfe_config::Listener;
use netkit_observability::RejectLabel;
use netkit_rate_limiting::{ConcurrencyLimit, Permit};
use pingora_core::apps::ServerApp;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{Notify, watch};

/// How long the accept loop waits after a failed `accept` before trying
/// again. The errors that persist (out of file descriptors or memory) would
/// otherwise spin the loop on a core and flood the log.
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(100);

/// The connections a set of listeners has open: capped across all of them
/// (`max_connections`), and waited for when the node drains.
#[derive(Debug)]
pub(crate) struct OpenConnections {
    limit: Arc<ConcurrencyLimit>,
    closed: Notify,
}

impl OpenConnections {
    pub(crate) fn new(max: usize) -> Arc<Self> {
        Arc::new(OpenConnections {
            limit: ConcurrencyLimit::new(Some(max)),
            closed: Notify::new(),
        })
    }

    /// How many connections are open.
    pub(crate) fn count(&self) -> usize {
        self.limit.in_use()
    }

    /// Resolves once no connection is open. Meant for when nothing accepts
    /// any more: a connection refused at the cap counts for a moment, and
    /// its refusal wakes nobody.
    pub(crate) async fn all_closed(&self) {
        loop {
            let closed = self.closed.notified();
            tokio::pin!(closed);
            // Registered before looking, so a close in between is not missed.
            closed.as_mut().enable();
            if self.count() == 0 {
                return;
            }
            closed.await;
        }
    }
}

/// A connection's place under both caps, given back when the connection's
/// task ends, however it ends.
struct Slot {
    permits: Option<(Permit, Permit)>,
    open: Arc<OpenConnections>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        drop(self.permits.take());
        self.open.closed.notify_waiters();
    }
}

/// Resolves when `cut` turns `true`; never if its sender goes away.
async fn cut_signalled(cut: &mut watch::Receiver<bool>) {
    if cut.wait_for(|cut| *cut).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Accept connections on `socket` until `shutdown` turns `true` (or its
/// sender goes away). The connections accepted until then watch the same
/// signal, to leave in an orderly way, and are cancelled when `cut` turns
/// `true`.
///
/// `config` is the listener as currently configured; it is read for every
/// accepted connection, and its id for every request, so its id and
/// protocol can change while the socket stays bound.
///
/// `open` bounds the connections open across all listeners; a limit of its
/// own bounds this listener's (`max_connections_listener`). When either is
/// reached the connection is closed at once and counted as rejected.
pub(crate) async fn run_listener<A>(
    edge: Arc<Edge<A>>,
    config: Arc<ArcSwap<Listener>>,
    socket: Arc<TcpListener>,
    open: Arc<OpenConnections>,
    mut shutdown: watch::Receiver<bool>,
    cut: watch::Receiver<bool>,
) where
    A: ServerApp + Send + Sync + 'static,
{
    let listener_connections =
        ConcurrencyLimit::new(Some(edge.shared.limits().max_connections_listener));
    loop {
        let accepted = tokio::select! {
            _ = shutdown.wait_for(|draining| *draining) => break,
            accepted = socket.accept() => accepted,
        };
        let (tcp, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, id = %config.load().id, "accept error");
                if pause_unless_shut_down(&mut shutdown, ACCEPT_ERROR_PAUSE).await {
                    break;
                }
                continue;
            }
        };

        let permits = open
            .limit
            .try_acquire()
            .and_then(|node| Ok((node, listener_connections.try_acquire()?)));
        let Ok(permits) = permits else {
            reject(&edge, "limit");
            continue;
        };
        let slot = Slot {
            permits: Some(permits),
            open: Arc::clone(&open),
        };

        let edge = Arc::clone(&edge);
        let config = Arc::clone(&config);
        let shutdown = shutdown.clone();
        let mut cut = cut.clone();
        tokio::spawn(async move {
            // Dropped last: the connection is accounted for before its place
            // is given back.
            let _slot = slot;
            tokio::select! {
                () = connection::serve(&edge, tcp, peer, config, shutdown) => {}
                () = cut_signalled(&mut cut) => {}
            }
        });
    }
    tracing::info!(id = %config.load().id, "listener draining, stop accepting");
}

/// Serve `socket` with `app`, at most `max_connections` at once, until
/// `shutdown` turns `true`: the accept loop then returns, and the
/// connections still open are left to finish (they see `shutdown` too).
///
/// This is the edge stripped to the socket and the cap: no TLS, no metrics,
/// no connection log, no [`Connections`](crate::listener::Connections), no
/// client timeouts beyond the app's own. It is for the node's own small
/// endpoints (`/healthz`, `/readyz`, `/metrics`), which must keep answering
/// while the proxy drains, and must not show up as client traffic.
pub async fn serve_plain<A>(
    socket: &TcpListener,
    app: Arc<A>,
    max_connections: usize,
    mut shutdown: watch::Receiver<bool>,
) where
    A: ServerApp + Send + Sync + 'static,
{
    let connections = ConcurrencyLimit::new(Some(max_connections));
    loop {
        let accepted = tokio::select! {
            _ = shutdown.wait_for(|stop| *stop) => return,
            accepted = socket.accept() => accepted,
        };
        let (tcp, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "accept error");
                if pause_unless_shut_down(&mut shutdown, ACCEPT_ERROR_PAUSE).await {
                    return;
                }
                continue;
            }
        };
        let Ok(permit) = connections.try_acquire() else {
            tracing::debug!(%peer, max_connections, "connection over the limit, closed");
            continue;
        };
        let app = Arc::clone(&app);
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let _permit = permit;
            connection::serve_unaccounted(&app, tcp, peer, &shutdown).await;
        });
    }
}

/// Wait for `pause`, unless `shutdown` turns `true` (or its sender goes away)
/// first. Returns `true` if the pause was cut short by the shutdown.
async fn pause_unless_shut_down(shutdown: &mut watch::Receiver<bool>, pause: Duration) -> bool {
    tokio::select! {
        () = tokio::time::sleep(pause) => false,
        _ = shutdown.wait_for(|shut_down| *shut_down) => true,
    }
}

fn reject<A>(edge: &Edge<A>, reason: &str) {
    edge.shared
        .metrics()
        .proxy
        .connections_rejected
        .get_or_create(&RejectLabel {
            reason: reason.to_string(),
        })
        .inc();
}

#[cfg(test)]
#[path = "acceptor_test.rs"]
mod tests;
