//! The node's listeners, on `netkit_listen`: what the config calls a
//! listener (an id, an address, a protocol) mapped onto the library's
//! sockets, which know only the address they are configured on.
//!
//! Reconciling, adopting and lending sockets, the limits, and the drain are
//! the library's. What is GFE's here is the mapping between listener ids
//! and addresses, the `edge::Edge` every accepted connection is served by,
//! the drain deadline, and the log lines an operator reads when listeners
//! come and go.

use crate::edge::{Edge, RequestHandler};
use gfe_config::{Listener, ListenerId};
use netkit_listen::{Drain, Drained, Limits, PeerRate};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// The most client addresses whose connection rate the node follows at
/// once (`client_connections_per_second`): a few megabytes. Beyond it,
/// clients quiet for a second are forgotten, and when none can be, a new
/// client's connection is served uncounted (`gfe_client_rate_untracked`).
const TRACKED_CLIENTS: NonZeroUsize = NonZeroUsize::new(65_536).unwrap();

/// The address a listener's socket is configured on.
fn socket_addr(listener: &Listener) -> SocketAddr {
    SocketAddr::new(listener.address, listener.port)
}

/// The address each listener of `listeners` is configured on, by id.
fn addresses(listeners: &[Listener]) -> HashMap<ListenerId, SocketAddr> {
    listeners
        .iter()
        .map(|listener| (listener.id.clone(), socket_addr(listener)))
        .collect()
}

/// A config's listeners, their new sockets bound, not applied yet. Dropping
/// it closes those sockets, leaving the running set untouched.
#[derive(Debug)]
pub struct Staged {
    inner: netkit_listen::Staged<Listener>,
    addresses: HashMap<ListenerId, SocketAddr>,
}

/// The listening sockets of a node, each accepted connection served by an
/// [`Edge`] answering with `H`.
pub struct Listeners<H: RequestHandler> {
    inner: netkit_listen::Listeners<Listener, Edge<H>>,
    drain_deadline: Duration,
    /// The address each running listener is configured on, by id, as last
    /// committed.
    addresses: Mutex<HashMap<ListenerId, SocketAddr>>,
}

impl<H: RequestHandler> Listeners<H> {
    /// An empty set, its connections served by `edge` under the connection
    /// limits of its shared state. Listeners stop accepting, and
    /// connections are asked to leave, when `drain` is triggered; whether
    /// the node drains (what `/readyz` tells) is `drain`'s to say.
    pub fn new(edge: Arc<Edge<H>>, drain: &Drain) -> Self {
        let shared = edge.shared();
        let limits = Limits {
            max_connections: shared.limits().max_connections,
            max_connections_per_listener: shared.limits().max_connections_listener,
            // A client that has been quiet may open a second's worth at once.
            connections_per_peer: shared
                .limits()
                .client_connections_per_second
                .map(|per_second| PeerRate {
                    per_second,
                    burst: per_second,
                    tracked_peers: TRACKED_CLIENTS,
                }),
        };
        let drain_deadline = shared.timeouts().drain_deadline;
        Listeners {
            inner: netkit_listen::Listeners::new(edge, limits, drain),
            drain_deadline,
            addresses: Mutex::new(HashMap::new()),
        }
    }

    fn addresses(&self) -> MutexGuard<'_, HashMap<ListenerId, SocketAddr>> {
        // Only ever replaced whole, so a panic while holding the lock does
        // not leave it half-written.
        self.addresses
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Hand the set sockets that are already bound and listening, each with
    /// the address a listener is configured on, to use instead of binding
    /// that address. The sockets the next committed config has no listener
    /// for are closed.
    pub fn adopt(&self, sockets: impl IntoIterator<Item = (SocketAddr, std::net::TcpListener)>) {
        self.inner.adopt(sockets);
    }

    /// A duplicate of every listening socket, with the address its listener
    /// is configured on, to hand to a successor. A duplicate stays open,
    /// and keeps queueing connections, after the set stops accepting.
    #[cfg(unix)]
    pub fn sockets(&self) -> io::Result<Vec<(SocketAddr, std::net::TcpListener)>> {
        self.inner.sockets()
    }

    /// Get the sockets `desired` needs that are not already listening: the
    /// adopted one for an address that has one, a newly bound one
    /// otherwise.
    ///
    /// Fails, naming the listeners the config adds, if any of their sockets
    /// cannot be had or two listeners share an address. The running set is
    /// then left as it is. One reconcile at a time; must be called from
    /// within a Tokio runtime.
    pub fn stage(&self, desired: &[Listener]) -> io::Result<Staged> {
        let running = self.addresses().clone();
        let entries = desired
            .iter()
            .map(|listener| (socket_addr(listener), listener.clone()))
            .collect();
        let inner = self.inner.stage(entries).map_err(|e| {
            let added: Vec<String> = desired
                .iter()
                .filter(|listener| !running.values().any(|addr| *addr == socket_addr(listener)))
                .map(|listener| format!("{} on {}", listener.id, socket_addr(listener)))
                .collect();
            io::Error::new(
                e.kind(),
                format!("{e} (listeners added: {})", added.join(", ")),
            )
        })?;
        Ok(Staged {
            inner,
            addresses: addresses(desired),
        })
    }

    /// Make the staged config's listeners the running set: stop accepting
    /// on the sockets it no longer names, rename or change the protocol of
    /// the ones it keeps (seen by the next request, and the next
    /// connection), and start accepting on the ones it adds. Connections
    /// already accepted are not interrupted.
    pub fn commit(&self, staged: Staged) {
        let Staged { inner, addresses } = staged;
        let mut running = self.addresses();
        self.inner.commit(inner);
        for (id, addr) in running.iter() {
            if !addresses.values().any(|kept| kept == addr) {
                tracing::info!(%addr, %id, "listener removed");
            }
        }
        for (id, addr) in &addresses {
            if !running.values().any(|was| was == addr) {
                let bound = self.inner.local_addr(*addr).unwrap_or(*addr);
                tracing::info!(addr = %bound, %id, "listener bound");
            }
        }
        *running = addresses;
    }

    /// The address listener `id` is bound to, if it is running. Tells which
    /// port a listener configured on port 0 got.
    pub fn local_addr(&self, id: &ListenerId) -> Option<SocketAddr> {
        let configured = *self.addresses().get(id)?;
        self.inner.local_addr(configured)
    }

    /// The listener a connection to `local` (an address of this host) was
    /// accepted on, if it is one of these. An IPv4 address belongs to a
    /// dual-stack (`::`) listener on its port.
    pub fn listener_at(&self, local: SocketAddr) -> Option<ListenerId> {
        self.inner
            .listener_at(local)
            .map(|listener| listener.id.clone())
    }

    /// How many accepted connections are open, over all listeners.
    pub fn open_connections(&self) -> usize {
        self.inner.open_connections()
    }

    /// How many connections were served without counting against their
    /// client's rate, because the node already followed as many clients as
    /// it can: what `gfe_client_rate_untracked` reports. Always 0 without
    /// `client_connections_per_second`.
    pub fn untracked_connections(&self) -> u64 {
        self.inner.untracked_connections()
    }

    /// Serve until the drain is triggered, then stop accepting and wait for
    /// the open connections to finish, at most the node's `drain_deadline`.
    /// What is still open then is cut, and accounted for with reason
    /// `shutdown`, before this returns. Returns as soon as the last
    /// connection is gone.
    pub async fn serve_until_drained(&self) -> Drained {
        let drained = self.inner.serve_until_drained(self.drain_deadline).await;
        if drained.stuck > 0 {
            tracing::error!(
                stuck = drained.stuck,
                "connections cut at the drain deadline did not end"
            );
        }
        drained
    }
}

impl<H: RequestHandler> std::fmt::Debug for Listeners<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listeners")
            .field("addresses", &*self.addresses())
            .field("open", &self.open_connections())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "listeners_test.rs"]
mod tests;
