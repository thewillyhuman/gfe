use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Unique identifier for a listener, referenced by [`crate::route::Route`].
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
    /// internal-only VIPs.
    Http,
    /// TLS-terminating HTTPS. The TLS policy and certificate store apply.
    Https,
}

/// A bound address + port that accepts client connections.
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
mod tests {
    use super::*;

    #[test]
    fn listener_serde_round_trip() {
        let json = r#"{"id":"https","address":"188.184.100.10","port":443,"protocol":"https"}"#;
        let l: Listener = serde_json::from_str(json).unwrap();
        assert_eq!(l.id, ListenerId("https".into()));
        assert_eq!(l.port, 443);
        assert!(l.is_tls());
    }
}
