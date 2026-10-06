//! What a request can know about the connection it arrived on, and what the
//! connection learns from its requests.
//!
//! Pingora hands the proxy a session, not the connection the edge accepted.
//! The edge therefore registers every connection it serves in
//! [`Connections`], under the two addresses of its socket, and the proxy
//! looks it up there once per request. The same record carries what flows
//! the other way: the connection needs to know how many requests it has
//! served and whether one is in flight, to tell an idle client from a slow
//! backend.

use arc_swap::ArcSwap;
use dashmap::DashMap;
use gfe_config::Listener;
use netkit_tls::TlsInfo;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

/// One client connection the node is serving.
#[derive(Debug)]
pub struct ConnInfo {
    client: SocketAddr,
    local: SocketAddr,
    /// The listener the connection was accepted on, as configured now: a
    /// reload may rename a listener while its connections stay open.
    listener: Arc<ArcSwap<Listener>>,
    tls: Option<TlsInfo>,
    requests: AtomicU64,
    in_flight: AtomicUsize,
    /// When the connection was registered: once established, and past its
    /// TLS handshake. The first request is waited for from then on.
    established: Instant,
    /// When the last request in flight ended, in milliseconds since
    /// `established`. Only meaningful while no request is in flight.
    idle_since_ms: AtomicU64,
    /// Woken when the last request in flight ends, for whoever enforces the
    /// client timeouts, which only run while the connection is idle.
    idle: Notify,
}

impl ConnInfo {
    /// A connection between `client` and the node's `local` address,
    /// accepted on `listener`. `tls` is what the handshake negotiated, and
    /// `None` on a plaintext connection.
    pub fn new(
        client: SocketAddr,
        local: SocketAddr,
        listener: Arc<ArcSwap<Listener>>,
        tls: Option<TlsInfo>,
    ) -> Arc<Self> {
        Arc::new(ConnInfo {
            client,
            local,
            listener,
            tls,
            requests: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
            established: Instant::now(),
            idle_since_ms: AtomicU64::new(0),
            idle: Notify::new(),
        })
    }

    /// The client's end of the connection.
    pub fn client(&self) -> SocketAddr {
        self.client
    }

    /// The node's end of the connection.
    pub fn local(&self) -> SocketAddr {
        self.local
    }

    /// The listener the connection was accepted on, as it is configured at
    /// the time of the call. Read it per request: its id is what routes
    /// refer to, and a reload may have changed it.
    pub fn listener(&self) -> Arc<Listener> {
        self.listener.load_full()
    }

    /// Whether the connection is encrypted. Decided when it was accepted: a
    /// reload that changes the listener's protocol applies to connections
    /// accepted afterwards.
    pub fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// What the TLS handshake negotiated; `None` on a plaintext connection.
    pub fn tls(&self) -> Option<&TlsInfo> {
        self.tls.as_ref()
    }

    /// The server name the client asked for in its handshake, if any.
    pub fn sni(&self) -> Option<&str> {
        self.tls.as_ref().and_then(|tls| tls.sni.as_deref())
    }

    /// Note that a request has arrived on the connection. It is in flight
    /// until the guard is dropped, which whoever answers it does once the
    /// response has been written to its end, or abandoned.
    pub fn begin_request(self: &Arc<Self>) -> RequestGuard {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        RequestGuard(Arc::clone(self))
    }

    /// How many requests have arrived on the connection so far.
    pub fn requests(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }

    /// Whether a request is in flight: received, and not answered to its end.
    pub fn has_request_in_flight(&self) -> bool {
        self.in_flight.load(Ordering::Acquire) > 0
    }

    /// When the connection was established (past its TLS handshake, if any).
    pub(crate) fn established(&self) -> Instant {
        self.established
    }

    /// Since when no request has been in flight: the end of the last one, or
    /// [`established`](Self::established) before the first. Only meaningful
    /// while [`has_request_in_flight`](Self::has_request_in_flight) is false.
    pub(crate) fn idle_since(&self) -> Instant {
        self.established + Duration::from_millis(self.idle_since_ms.load(Ordering::Relaxed))
    }

    /// Resolves once the last request in flight has ended. A request that
    /// ended before this is called still counts: the wake-up is kept for the
    /// next waiter, which then only has to look again.
    pub(crate) async fn went_idle(&self) {
        self.idle.notified().await;
    }
}

/// A request in flight on a connection, until dropped.
#[derive(Debug)]
pub struct RequestGuard(Arc<ConnInfo>);

impl Drop for RequestGuard {
    fn drop(&mut self) {
        let conn = &self.0;
        let idle_since = u64::try_from(conn.established.elapsed().as_millis()).unwrap_or(u64::MAX);
        // Stored before the count is released, so that whoever sees no
        // request in flight also sees when the connection went idle.
        conn.idle_since_ms.store(idle_since, Ordering::Relaxed);
        if conn.in_flight.fetch_sub(1, Ordering::Release) == 1 {
            conn.idle.notify_one();
        }
    }
}

/// The connections the node is serving, by the two addresses of their socket.
///
/// The pair is unique among open TCP connections, and it is what both sides
/// have at hand: the edge when it accepts, the proxy from the session of a
/// request.
#[derive(Debug, Default)]
pub struct Connections {
    by_addresses: DashMap<(SocketAddr, SocketAddr), Arc<ConnInfo>>,
}

impl Connections {
    /// An empty table.
    pub fn new() -> Arc<Self> {
        Arc::new(Connections::default())
    }

    /// Make `conn` findable by its addresses for as long as the returned
    /// registration lives.
    pub fn register(self: &Arc<Self>, conn: Arc<ConnInfo>) -> Registration {
        let key = (conn.client, conn.local);
        self.by_addresses.insert(key, Arc::clone(&conn));
        Registration {
            connections: Arc::clone(self),
            conn,
        }
    }

    /// The connection between `client` and the node's `local` address, if
    /// the node is serving one.
    pub fn lookup(&self, client: SocketAddr, local: SocketAddr) -> Option<Arc<ConnInfo>> {
        self.by_addresses
            .get(&(client, local))
            .map(|entry| Arc::clone(entry.value()))
    }

    /// How many connections are registered.
    pub fn len(&self) -> usize {
        self.by_addresses.len()
    }

    /// Whether no connection is registered.
    pub fn is_empty(&self) -> bool {
        self.by_addresses.is_empty()
    }
}

/// A connection's place in [`Connections`], given up when dropped.
#[derive(Debug)]
pub struct Registration {
    connections: Arc<Connections>,
    conn: Arc<ConnInfo>,
}

impl Registration {
    /// The registered connection.
    pub fn conn(&self) -> &Arc<ConnInfo> {
        &self.conn
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        // The kernel may hand the same pair of addresses to a new connection
        // as soon as this one is closed, and that one may register before
        // this registration is dropped: only remove what is still ours.
        self.connections
            .by_addresses
            .remove_if(&(self.conn.client, self.conn.local), |_, registered| {
                Arc::ptr_eq(registered, &self.conn)
            });
    }
}

#[cfg(test)]
#[path = "conn_info_test.rs"]
mod tests;
