//! Builds the rustls [`ServerConfig`] enforcing the fleet TLS policy:
//! minimum protocol version and ALPN advertisement.

use crate::resolver::SniResolver;
use gfe_types::{GfeError, MinVersion};
use rustls::ServerConfig;
use std::sync::Arc;

/// ALPN protocols advertised on HTTPS listeners, in preference order.
pub const ALPN_PROTOCOLS: &[&[u8]] = &[b"h2", b"http/1.1"];

/// Build a `ServerConfig` from the SNI resolver and the configured minimum
/// TLS version. Uses the `ring` crypto provider explicitly so no process-wide
/// default provider needs to be installed.
pub fn server_config(
    resolver: Arc<SniResolver>,
    min_version: MinVersion,
) -> Result<ServerConfig, GfeError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let versions: &[&rustls::SupportedProtocolVersion] = match min_version {
        MinVersion::Tls12 => rustls::ALL_VERSIONS,
        MinVersion::Tls13 => &[&rustls::version::TLS13],
    };

    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| GfeError::Tls(format!("invalid TLS version set: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|p| p.to_vec()).collect();

    // Enable session resumption tickets (TLS 1.2 tickets / TLS 1.3 PSK). This
    // is a per-node rotating ticketer, which speeds up reconnects to the *same*
    // node. Fleet-shared ticket keys (so a resumed session can land on any
    // node) require a custom file-keyed ticketer and are a documented
    // follow-up; resumption degrades gracefully to a full handshake across
    // nodes in the meantime.
    if let Ok(ticketer) = rustls::crypto::ring::Ticketer::new() {
        config.ticketer = ticketer;
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert_store::CertStore;

    #[test]
    fn builds_server_config() {
        let resolver = Arc::new(SniResolver::new(CertStore::default()));
        let cfg = server_config(resolver.clone(), MinVersion::Tls12).unwrap();
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        // TLS 1.3-only also builds.
        assert!(server_config(resolver, MinVersion::Tls13).is_ok());
    }
}
