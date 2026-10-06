//! Listeners: where a node accepts client connections.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Unique identifier for a listener, referenced by [`crate::Route`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ListenerId(pub String);

impl std::fmt::Display for ListenerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether a listener terminates TLS or serves plaintext HTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenProtocol {
    /// Plaintext HTTP. Used for HTTP→HTTPS redirect listeners and
    /// internal-only addresses.
    Http,
    /// TLS-terminating HTTPS. The TLS policy and certificate store apply.
    Https,
}

/// Binds an address and a port, and accepts client connections on them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub id: ListenerId,
    pub address: IpAddr,
    pub port: u16,
    pub protocol: ListenProtocol,
}

impl Listener {
    /// `true` when this listener terminates TLS.
    pub fn is_tls(&self) -> bool {
        matches!(self.protocol, ListenProtocol::Https)
    }
}

#[cfg(test)]
#[path = "listener_test.rs"]
mod tests;
