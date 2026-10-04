//! The set of listening sockets, reconciled against the dynamic config.
//!
//! A socket is identified by the address it is bound to. Everything else
//! about a listener is read while serving: whether it terminates TLS per
//! accepted connection, its id per request. So it can change without
//! rebinding. Reconciling a new config
//! therefore never disturbs a socket whose address is unchanged.
//!
//! Reconciliation is two-phase so a reload stays all-or-nothing: [`stage`]
//! binds the sockets a config adds (the only step that can fail), and
//! [`commit`] makes the config's listeners the running set.
//!
//! A socket does not have to be bound here. A node that replaces a running
//! one is handed that node's sockets, [adopts] them, and so serves the
//! connections waiting on them; the running node [lends] them for that.
//!
//! [`stage`]: ListenerSet::stage
//! [`commit`]: ListenerSet::commit
//! [adopts]: ListenerSet::adopt
//! [lends]: ListenerSet::sockets

use crate::config::{Listener, ListenerId};
use crate::server::acceptor;
use crate::server::{RequestHandler, ServerShared};
use arc_swap::ArcSwap;
use rustls::ServerConfig;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;

/// Pending-connection queue length requested for listening sockets (the
/// kernel caps it at `net.core.somaxconn`).
const LISTEN_BACKLOG: u32 = 1024;

/// How often the drain loop looks for remaining connections.
const DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(100);

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

/// The running listeners of a node.
pub struct ListenerSet<H> {
    shared: Arc<ServerShared>,
    /// Answers the requests of the connections the listeners accept.
    handler: Arc<H>,
    server_config: Arc<ServerConfig>,
    /// Bounds concurrent connections across all listeners.
    connections: Arc<Semaphore>,
    shutdown: watch::Receiver<bool>,
    running: Mutex<HashMap<SocketAddr, Running>>,
    /// Listening sockets handed to the set, until the next commit.
    adopted: Mutex<HashMap<SocketAddr, std::net::TcpListener>>,
}

impl<H: RequestHandler> ListenerSet<H> {
    /// An empty set, whose connections share `shared` and have their
    /// requests answered by `handler`. Listeners stop accepting when
    /// `shutdown` turns `true`.
    pub fn new(
        shared: Arc<ServerShared>,
        handler: Arc<H>,
        server_config: Arc<ServerConfig>,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        let connections = Arc::new(Semaphore::new(shared.limits.max_connections));
        ListenerSet {
            shared,
            handler,
            server_config,
            connections,
            shutdown,
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
    #[cfg(unix)]
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
                config.clone(),
                socket.clone(),
                self.shared.clone(),
                self.handler.clone(),
                self.server_config.clone(),
                self.connections.clone(),
                self.shutdown.clone(),
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
    /// belongs to, if it is one of the proxy's listeners.
    pub fn listener_at(&self, local: SocketAddr) -> Option<ListenerId> {
        self.running()
            .values()
            .find(|listener| {
                let bound = listener.local_addr;
                bound.port() == local.port()
                    && (bound.ip().is_unspecified() || bound.ip() == local.ip())
            })
            .map(|listener| listener.config.load().id.clone())
    }

    /// Serve until the shutdown signal, then stop accepting and wait for the
    /// open connections to finish, at most `drain_deadline`.
    pub async fn serve_until_drained(&self) {
        let mut shutdown = self.shutdown.clone();
        while !*shutdown.borrow_and_update() {
            if shutdown.changed().await.is_err() {
                break;
            }
        }

        let accept_loops: Vec<JoinHandle<()>> = self
            .running()
            .drain()
            .map(|(_, listener)| listener.accept_loop)
            .collect();
        for accept_loop in accept_loops {
            let _ = accept_loop.await;
        }

        let deadline = Instant::now() + self.shared.timeouts.drain_deadline;
        loop {
            let active = self.shared.metrics.proxy.connections_active.get();
            if active <= 0 {
                break;
            }
            if Instant::now() >= deadline {
                tracing::warn!(active, "drain deadline elapsed with connections still open");
                break;
            }
            tokio::time::sleep(DRAIN_POLL_INTERVAL).await;
        }
    }
}

/// Accept on a socket that is already bound and listening.
fn listen_on(socket: std::net::TcpListener) -> io::Result<TcpListener> {
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket)
}

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
