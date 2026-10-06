//! What a request can know about the connection it arrived on.
use arc_swap::ArcSwap;
use gfe_config::Listener;
use netkit_tls::TlsInfo;
use std::net::SocketAddr;
use std::sync::Arc;

/// One client connection the node is serving, as the requests that arrive
/// on it see it.
#[derive(Debug)]
pub struct ConnInfo {
    client: SocketAddr,
    local: SocketAddr,
    /// The listener the connection was accepted on, as configured now: a
    /// reload may rename a listener while its connections stay open.
    listener: Arc<ArcSwap<Listener>>,
    tls: Option<TlsInfo>,
}

impl ConnInfo {
    /// A connection between `client` and the node's `local` address,
    /// accepted on `listener`. `tls` is what the handshake negotiated, and
    /// `None` on a plaintext connection.
    ///
    /// Both addresses are kept in their canonical form: an IPv4 client that
    /// reached a dual-stack socket is `192.0.2.1`, not `::ffff:192.0.2.1`,
    /// so that logs and hashes see one address per client.
    pub fn new(
        client: SocketAddr,
        local: SocketAddr,
        listener: Arc<ArcSwap<Listener>>,
        tls: Option<TlsInfo>,
    ) -> Self {
        ConnInfo {
            client: canonical(client),
            local: canonical(local),
            listener,
            tls,
        }
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
}

/// `address` with an IPv4-mapped IPv6 address turned back into IPv4.
fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

#[cfg(test)]
#[path = "conn_info_test.rs"]
mod tests;
