//! The set of listening sockets, reconciled against the dynamic config.
//!
//! A socket is identified by the address it is bound to. Everything else
//! about a listener is read while serving: whether it terminates TLS per
//! accepted connection, its id per request. So it can change without
//! rebinding. Reconciling a new config therefore never disturbs a socket
//! whose address is unchanged.
//!
//! Reconciliation is two-phase so a reload stays all-or-nothing: [`stage`]
//! binds the sockets a config adds (the only step that can fail), and
//! [`commit`] makes the config's listeners the running set.
//!
//! A socket does not have to be bound here. A node that replaces a running
//! one is handed that node's sockets, [adopts] them, and so serves the
//! connections waiting on them; the running node [lends] them for that.
//!
//! [`stage`]: Listeners::stage
//! [`commit`]: Listeners::commit
//! [adopts]: Listeners::adopt
//! [lends]: Listeners::sockets

use crate::listener::acceptor::{self, OpenConnections};
use crate::listener::connection::Edge;
use crate::listener::{Connections, Shared};
use arc_swap::ArcSwap;
use gfe_config::{Listener, ListenerId};
use netkit_tls::Acceptor;
use pingora_core::apps::ServerApp;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// Pending-connection queue length requested for listening sockets (the
/// kernel caps it at `net.core.somaxconn`).
const LISTEN_BACKLOG: u32 = 1024;

/// How long the connections cut at the drain deadline may take to be
/// accounted for. Cancelling a task takes no time unless it is stuck in
/// something synchronous, which this bounds.
const CUT_GRACE: Duration = Duration::from_secs(1);

/// The address a listener's socket is bound to.
fn socket_addr(listener: &Listener) -> SocketAddr {
    SocketAddr::new(listener.address, listener.port)
}

/// One accepting socket.
struct Running {
    /// The listener as currently configured, read for each new connection.
    config: Arc<ArcSwap<Listener>>,
    /// Shared with the accept loop, so the socket can be lent while it
    /// accepts.
    socket: Arc<TcpListener>,
    /// The address actually bound (differs from the configured one only for
    /// port 0).
    local_addr: SocketAddr,
    accept_loop: JoinHandle<()>,
}

/// Sockets bound for a config that is not applied yet. Dropping it closes
/// them, leaving the running set untouched.
pub struct Staged {
    desired: Vec<Listener>,
    bound: Vec<(Listener, TcpListener)>,
}

impl std::fmt::Debug for Staged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Staged")
            .field("desired", &self.desired)
            .field("bound", &self.bound.len())
            .finish()
    }
}

/// The listening sockets of a node, and the connections accepted on them,
/// each handed to the Pingora application `A`.
pub struct Listeners<A> {
    edge: Arc<Edge<A>>,
    open: Arc<OpenConnections>,
    shutdown: watch::Receiver<bool>,
    /// Turned `true` at the drain deadline: what is still open is cut.
    cut: watch::Sender<bool>,
    running: Mutex<HashMap<SocketAddr, Running>>,
    /// Listening sockets handed to the set, until the next commit.
    adopted: Mutex<HashMap<SocketAddr, std::net::TcpListener>>,
}

impl<A> Listeners<A>
where
    A: ServerApp + Send + Sync + 'static,
{
    /// An empty set. Its connections share `shared`, are served by `app`,
    /// terminate TLS with `tls` on HTTPS listeners, and are registered in
    /// `connections` for `app` to find. Listeners stop accepting, and
    /// connections are asked to leave, when `shutdown` turns `true` (see
    /// [`Drain`](crate::listener::Drain)).
    ///
    /// The client timeouts rely on `app` telling each connection when a
    /// request begins and ends ([`ConnInfo::begin_request`]): a connection
    /// that never reports one is taken for a client that sent nothing.
    ///
    /// [`ConnInfo::begin_request`]: crate::listener::ConnInfo::begin_request
    pub fn new(
        shared: Arc<Shared>,
        app: Arc<A>,
        tls: Acceptor,
        connections: Arc<Connections>,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        let open = OpenConnections::new(shared.limits().max_connections);
        let (cut, _) = watch::channel(false);
        Listeners {
            edge: Arc::new(Edge {
                shared,
                app,
                tls,
                connections,
            }),
            open,
            shutdown,
            cut,
            running: Mutex::new(HashMap::new()),
            adopted: Mutex::new(HashMap::new()),
        }
    }

    fn running(&self) -> MutexGuard<'_, HashMap<SocketAddr, Running>> {
        // Every critical section leaves the map consistent, so a panic while
        // holding the lock does not invalidate it.
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn adopted(&self) -> MutexGuard<'_, HashMap<SocketAddr, std::net::TcpListener>> {
        self.adopted.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hand the set sockets that are already bound and listening, each with
    /// the address a listener is configured on to use it.
    ///
    /// The next config to be staged listens on them instead of binding those
    /// addresses, so the connections waiting on them are served. The sockets
    /// that config has no listener for are closed when it is committed.
    pub fn adopt(&self, sockets: impl IntoIterator<Item = (SocketAddr, std::net::TcpListener)>) {
        self.adopted().extend(sockets);
    }

    /// A duplicate of every listening socket, with the address its listener
    /// is configured on. A duplicate stays open, and keeps queueing
    /// connections, after the set stops accepting on its own copy.
    pub fn sockets(&self) -> io::Result<Vec<(SocketAddr, std::net::TcpListener)>> {
        use std::os::fd::AsFd;
        self.running()
            .iter()
            .map(|(addr, listener)| {
                let duplicate = listener.socket.as_fd().try_clone_to_owned()?;
                Ok((*addr, std::net::TcpListener::from(duplicate)))
            })
            .collect()
    }

    /// Get the sockets `desired` needs that are not already listening: the
    /// adopted one for an address that has one, a newly bound one otherwise.
    ///
    /// Fails if any of them cannot be had. The running set is then left as
    /// it is; adopted sockets taken before the failure are closed. Must be
    /// called from within a Tokio runtime.
    pub fn stage(&self, desired: &[Listener]) -> io::Result<Staged> {
        let running = self.running();
        let mut bound = Vec::new();
        for listener in desired {
            let addr = socket_addr(listener);
            if !running.contains_key(&addr) {
                let adopted = self.adopted().remove(&addr);
                let socket = match adopted {
                    Some(socket) => listen_on(socket),
                    None => bind(addr),
                }
                .map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("binding listener {} on {addr}: {e}", listener.id),
                    )
                })?;
                bound.push((listener.clone(), socket));
            }
        }
        Ok(Staged {
            desired: desired.to_vec(),
            bound,
        })
    }

    /// Make the staged config's listeners the running set: stop accepting on
    /// sockets it no longer names, update the ones it keeps, and start
    /// accepting on the ones it adds. Connections already accepted on a
    /// stopped socket are not interrupted. Adopted sockets it did not use
    /// are closed.
    pub fn commit(&self, staged: Staged) {
        let mut running = self.running();

        let desired: HashSet<SocketAddr> = staged.desired.iter().map(socket_addr).collect();
        running.retain(|addr, listener| {
            let keep = desired.contains(addr);
            if !keep {
                // The accept loop only ever waits in `accept`, so aborting it
                // closes the socket without dropping an accepted connection.
                listener.accept_loop.abort();
                tracing::info!(%addr, id = %listener.config.load().id, "listener removed");
            }
            keep
        });

        for listener in &staged.desired {
            if let Some(kept) = running.get(&socket_addr(listener)) {
                kept.config.store(Arc::new(listener.clone()));
            }
        }

        for (listener, socket) in staged.bound {
            let addr = socket_addr(&listener);
            let local_addr = socket.local_addr().unwrap_or(addr);
            tracing::info!(addr = %local_addr, id = %listener.id, "listener bound");
            let config = Arc::new(ArcSwap::from_pointee(listener));
            let socket = Arc::new(socket);
            let accept_loop = tokio::spawn(acceptor::run_listener(
                Arc::clone(&self.edge),
                Arc::clone(&config),
                Arc::clone(&socket),
                Arc::clone(&self.open),
                self.shutdown.clone(),
                self.cut.subscribe(),
            ));
            running.insert(
                addr,
                Running {
                    config,
                    socket,
                    local_addr,
                    accept_loop,
                },
            );
        }

        for (addr, _) in self.adopted().drain() {
            tracing::info!(%addr, "adopted socket has no listener, closed");
        }
    }

    /// The address listener `id` is bound to, if it is running. Useful when
    /// the configured port is 0.
    pub fn local_addr(&self, id: &ListenerId) -> Option<SocketAddr> {
        self.running()
            .values()
            .find(|listener| listener.config.load().id == *id)
            .map(|listener| listener.local_addr)
    }

    /// The listener a connection accepted on the node's address `local`
    /// belongs to, if it is one of these listeners. An IPv4 address matches
    /// a dual-stack (`::`) listener on its port.
    pub fn listener_at(&self, local: SocketAddr) -> Option<ListenerId> {
        self.running()
            .values()
            .find(|listener| {
                let bound = listener.local_addr;
                bound.port() == local.port()
                    && (bound.ip().is_unspecified()
                        || bound.ip().to_canonical() == local.ip().to_canonical())
            })
            .map(|listener| listener.config.load().id.clone())
    }

    /// Serve until the shutdown signal, then drain: stop accepting, and wait
    /// for the open connections to finish, at most `drain_deadline`.
    ///
    /// Half-way through, the application's `cleanup` is called (Pingora's
    /// proxy then drops the connections still waiting for a request). What
    /// is still open at the deadline is cut, and accounted for with reason
    /// `shutdown`, before this returns.
    pub async fn serve_until_drained(&self) {
        let mut shutdown = self.shutdown.clone();
        // The sender going away means the node is going away, too.
        let _ = shutdown.wait_for(|draining| *draining).await;
        let started = Instant::now();

        let accept_loops: Vec<JoinHandle<()>> = self
            .running()
            .drain()
            .map(|(_, listener)| listener.accept_loop)
            .collect();
        for accept_loop in accept_loops {
            let _ = accept_loop.await;
        }

        let drain_deadline = self.edge.shared.timeouts().drain_deadline;
        let deadline = started + drain_deadline;
        let cleanup_at = started + drain_deadline / 2;
        let mut cleaned_up = false;
        loop {
            tokio::select! {
                () = self.open.all_closed() => return,
                () = tokio::time::sleep_until(cleanup_at), if !cleaned_up => {
                    self.edge.app.cleanup().await;
                    cleaned_up = true;
                }
                () = tokio::time::sleep_until(deadline) => break,
            }
        }

        tracing::warn!(
            open = self.open.count(),
            "drain deadline elapsed with connections still open, cutting them"
        );
        self.cut.send_replace(true);
        if tokio::time::timeout(CUT_GRACE, self.open.all_closed())
            .await
            .is_err()
        {
            tracing::error!(
                open = self.open.count(),
                "connections cut at the drain deadline did not end"
            );
        }
    }
}

impl<A> std::fmt::Debug for Listeners<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listeners")
            .field("open", &self.open.count())
            .finish_non_exhaustive()
    }
}

/// Accept on a socket that is already bound and listening.
fn listen_on(socket: std::net::TcpListener) -> io::Result<TcpListener> {
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket)
}

/// A socket listening on `addr`. An IPv6 wildcard address accepts IPv4
/// clients too, unless the host disables it (`net.ipv6.bindv6only`).
fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    // Lets a restarted node rebind while old connections linger in TIME_WAIT.
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(LISTEN_BACKLOG)
}

#[cfg(test)]
#[path = "listeners_test.rs"]
mod tests;
