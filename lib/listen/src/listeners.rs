//! The set of listening sockets of a process, reconciled against its
//! config.
//!
//! A socket is identified by the address it is configured on. Everything
//! else about a listener is the caller's (`T`), read for each accepted
//! connection, so it can change without rebinding. Reconciling a new config
//! therefore never disturbs a socket whose address is unchanged.
//!
//! Reconciliation is two-phase so a reload stays all-or-nothing: [`stage`]
//! gets the sockets a config adds (the only step that can fail), and
//! [`commit`] makes the config's listeners the running set.
//!
//! A socket does not have to be bound here. A process that replaces a
//! running one is handed that process's sockets, [adopts] them, and so
//! serves the connections waiting on them; the running process [lends] them
//! for that.
//!
//! [`stage`]: Listeners::stage
//! [`commit`]: Listeners::commit
//! [adopts]: Listeners::adopt
//! [lends]: Listeners::sockets

use crate::accept::{self, Limits, OpenConnections, Serve};
use crate::drain::Drain;
use arc_swap::ArcSwap;
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

/// How long the connections cut at the drain deadline may take to end.
/// Dropping a task takes no time unless it is stuck in something
/// synchronous, which this bounds.
const CUT_GRACE: Duration = Duration::from_secs(1);

/// One accepting socket.
#[derive(Debug)]
struct Running<T> {
    /// What the caller attached to the listener, read for each connection.
    listener: Arc<ArcSwap<T>>,
    /// Shared with the accept loop, so the socket can be lent while it
    /// accepts.
    socket: Arc<TcpListener>,
    /// The address actually bound (differs from the configured one only for
    /// port 0).
    local_addr: SocketAddr,
    accept_loop: JoinHandle<()>,
}

/// Sockets got for a config that is not applied yet. Dropping it closes
/// them, leaving the running set untouched.
#[derive(Debug)]
pub struct Staged<T> {
    desired: Vec<(SocketAddr, T)>,
    bound: HashMap<SocketAddr, TcpListener>,
}

/// How a drain ended: with every connection closed by its own code, or
/// with some cut at the deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Drained {
    /// Connections still open at the deadline, and so cut. Zero when every
    /// connection ended in time.
    pub cut: usize,
    /// Connections still open a moment after the cut: their task is stuck
    /// in something that does not yield. Zero unless the code serving them
    /// blocks.
    pub stuck: usize,
}

/// The listening sockets of a process: bound and released as its config
/// changes, each accepted connection handed to `S`, with the `T` the caller
/// attached to the listener it was accepted on.
#[derive(Debug)]
pub struct Listeners<T, S> {
    serve: Arc<S>,
    limits: Limits,
    open: Arc<OpenConnections>,
    drain: watch::Receiver<bool>,
    /// Turned `true` at the drain deadline: what is still open is cut.
    cut: watch::Sender<bool>,
    running: Mutex<HashMap<SocketAddr, Running<T>>>,
    /// Listening sockets handed to the set, until the next commit.
    adopted: Mutex<HashMap<SocketAddr, std::net::TcpListener>>,
}

impl<T, S> Listeners<T, S>
where
    T: Send + Sync + 'static,
    S: Serve<T>,
{
    /// An empty set. Its connections are served by `serve`, under `limits`.
    /// Listeners stop accepting, and connections are told to leave, when
    /// `drain` is triggered.
    pub fn new(serve: Arc<S>, limits: Limits, drain: &Drain) -> Self {
        let (cut, _) = watch::channel(false);
        Listeners {
            serve,
            limits,
            open: OpenConnections::new(limits.max_connections),
            drain: drain.subscribe(),
            cut,
            running: Mutex::new(HashMap::new()),
            adopted: Mutex::new(HashMap::new()),
        }
    }

    fn running(&self) -> MutexGuard<'_, HashMap<SocketAddr, Running<T>>> {
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
            .map(|(addr, running)| {
                let duplicate = running.socket.as_fd().try_clone_to_owned()?;
                Ok((*addr, std::net::TcpListener::from(duplicate)))
            })
            .collect()
    }

    /// Get the sockets `desired` needs that are not already listening: the
    /// adopted one for an address that has one, a newly bound one otherwise.
    /// Each entry is the address a listener is configured on and what the
    /// caller attaches to it.
    ///
    /// Fails if an address is named twice (`InvalidInput`), or if any socket
    /// cannot be had. The running set is then left as it is; adopted
    /// sockets taken before the failure are closed. Must be called from
    /// within a Tokio runtime.
    pub fn stage(&self, desired: Vec<(SocketAddr, T)>) -> io::Result<Staged<T>> {
        let mut named = HashSet::new();
        if let Some((addr, _)) = desired.iter().find(|(addr, _)| !named.insert(*addr)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{addr} is named by more than one listener"),
            ));
        }

        let running = self.running();
        let mut bound = HashMap::new();
        for (addr, _) in &desired {
            if running.contains_key(addr) {
                continue;
            }
            let adopted = self.adopted().remove(addr);
            let socket = match adopted {
                Some(socket) => listen_on(socket).map_err(|e| {
                    io::Error::new(e.kind(), format!("listening on adopted {addr}: {e}"))
                }),
                None => bind(*addr)
                    .map_err(|e| io::Error::new(e.kind(), format!("binding {addr}: {e}"))),
            }?;
            bound.insert(*addr, socket);
        }
        Ok(Staged { desired, bound })
    }

    /// Make the staged config's listeners the running set: stop accepting on
    /// sockets it no longer names, replace what is attached to the ones it
    /// keeps, and start accepting on the ones it adds. Connections already
    /// accepted on a stopped socket are not interrupted. Adopted sockets it
    /// did not use are closed.
    ///
    /// Meant to follow the [`stage`](Listeners::stage) that made `staged`,
    /// one reconcile at a time.
    pub fn commit(&self, staged: Staged<T>) {
        let Staged { desired, mut bound } = staged;
        let mut running = self.running();

        let named: HashSet<SocketAddr> = desired.iter().map(|(addr, _)| *addr).collect();
        running.retain(|addr, listener| {
            let keep = named.contains(addr);
            if !keep {
                // The accept loop only ever waits in `accept`, so aborting it
                // closes the socket without dropping an accepted connection.
                listener.accept_loop.abort();
                tracing::debug!(%addr, "listener removed");
            }
            keep
        });

        for (addr, attached) in desired {
            if let Some(kept) = running.get(&addr) {
                kept.listener.store(Arc::new(attached));
                continue;
            }
            let Some(socket) = bound.remove(&addr) else {
                tracing::warn!(%addr, "committed without a socket: stage and commit raced");
                continue;
            };
            let local_addr = socket.local_addr().unwrap_or(addr);
            tracing::debug!(%addr, %local_addr, "listener bound");
            let listener = Arc::new(ArcSwap::from_pointee(attached));
            let socket = Arc::new(socket);
            let accept_loop = tokio::spawn(accept::run_listener(
                Arc::clone(&self.serve),
                Arc::clone(&listener),
                Arc::clone(&socket),
                Arc::clone(&self.open),
                self.limits.max_connections_per_listener,
                self.drain.clone(),
                self.cut.subscribe(),
            ));
            running.insert(
                addr,
                Running {
                    listener,
                    socket,
                    local_addr,
                    accept_loop,
                },
            );
        }

        for (addr, _) in self.adopted().drain() {
            tracing::debug!(%addr, "adopted socket has no listener, closed");
        }
    }

    /// The address the listener configured on `configured` is bound to, if
    /// it is running. Differs from `configured` only when its port is 0.
    pub fn local_addr(&self, configured: SocketAddr) -> Option<SocketAddr> {
        self.running()
            .get(&configured)
            .map(|running| running.local_addr)
    }

    /// What is attached to the listener a connection to `local` (an address
    /// of this host) was accepted on, if it is one of these listeners. An
    /// IPv4 address belongs to a dual-stack (`::`) listener on its port.
    pub fn listener_at(&self, local: SocketAddr) -> Option<Arc<T>> {
        self.running()
            .values()
            .find(|running| {
                let bound = running.local_addr;
                bound.port() == local.port()
                    && (bound.ip().is_unspecified()
                        || bound.ip().to_canonical() == local.ip().to_canonical())
            })
            .map(|running| running.listener.load_full())
    }

    /// How many accepted connections are open, over all listeners.
    pub fn open_connections(&self) -> usize {
        self.open.count()
    }

    /// Serve until the drain is triggered, then stop accepting and wait for
    /// the open connections to finish, at most `deadline`. What is still
    /// open then is cut (its [`Serve::serve`] future dropped), and given a
    /// moment to end, before this returns. Returns as soon as the last
    /// connection is gone.
    pub async fn serve_until_drained(&self, deadline: Duration) -> Drained {
        let mut drain = self.drain.clone();
        // The drain going away means the process is going away, too.
        let _ = drain.wait_for(|draining| *draining).await;
        let deadline = Instant::now() + deadline;

        let accept_loops: Vec<JoinHandle<()>> = self
            .running()
            .drain()
            .map(|(_, running)| running.accept_loop)
            .collect();
        for accept_loop in accept_loops {
            let _ = accept_loop.await;
        }

        if tokio::time::timeout_at(deadline, self.open.all_closed())
            .await
            .is_ok()
        {
            return Drained { cut: 0, stuck: 0 };
        }

        let cut = self.open.count();
        tracing::warn!(open = cut, "drain deadline passed, cutting what is open");
        self.cut.send_replace(true);
        let stuck = match tokio::time::timeout(CUT_GRACE, self.open.all_closed()).await {
            Ok(()) => 0,
            Err(_) => self.open.count(),
        };
        Drained { cut, stuck }
    }
}

impl<T, S> Drop for Listeners<T, S> {
    /// Stop accepting, which closes the sockets. Connections already
    /// accepted are not interrupted.
    fn drop(&mut self) {
        let running = self
            .running
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        for running in running.values() {
            running.accept_loop.abort();
        }
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
    // Lets a restarted process rebind while old connections linger in
    // TIME_WAIT.
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(LISTEN_BACKLOG)
}

#[cfg(test)]
#[path = "listeners_test.rs"]
mod tests;
