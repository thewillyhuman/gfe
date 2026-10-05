//! Builds the rustls [`ServerConfig`] enforcing the fleet TLS policy:
//! minimum protocol version, ALPN advertisement, session resumption.

use crate::{SniResolver, TlsError};
use gfe_config::MinVersion;
use rustls::ServerConfig;
use std::sync::Arc;

/// ALPN protocols advertised on HTTPS listeners, in preference order.
pub const ALPN_PROTOCOLS: &[&[u8]] = &[b"h2", b"http/1.1"];

/// Build a `ServerConfig` from the SNI resolver and the configured minimum
/// TLS version (`1.2` allows TLS 1.2 and 1.3, `1.3` allows TLS 1.3 only).
/// Uses the `ring` crypto provider explicitly so no process-wide default
/// provider needs to be installed.
///
/// Session resumption (TLS 1.2 tickets, TLS 1.3 PSK) uses a per-node
/// rotating ticketer, which speeds up reconnects to the *same* node. The
/// bootstrap key `[tls] ticket_key_file` (fleet-shared ticket keys, so that a
/// resumed session can land on any node) is parsed by `gfe-config` but not
/// used: it would need a custom file-keyed ticketer. Resumption across nodes
/// degrades to a full handshake.
pub fn server_config(
    resolver: Arc<SniResolver>,
    min_version: MinVersion,
) -> Result<ServerConfig, TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let versions: &[&rustls::SupportedProtocolVersion] = match min_version {
        MinVersion::Tls12 => rustls::ALL_VERSIONS,
        MinVersion::Tls13 => &[&rustls::version::TLS13],
    };

    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(TlsError::Policy)?
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|p| p.to_vec()).collect();
    // Fails only when the system has no randomness, in which case no TLS
    // works at all: refuse to start rather than run without resumption.
    config.ticketer = rustls::crypto::ring::Ticketer::new().map_err(TlsError::Policy)?;

    Ok(config)
}

#[cfg(test)]
#[path = "policy_test.rs"]
mod tests;
