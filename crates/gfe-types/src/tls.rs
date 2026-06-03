use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Minimum TLS protocol version offered on HTTPS listeners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum MinVersion {
    #[serde(rename = "1.2")]
    #[default]
    Tls12,
    #[serde(rename = "1.3")]
    Tls13,
}

/// A certificate entry in the dynamic config. Binds one or more SNI names to
/// a PEM certificate chain + private key on disk, or marks a default
/// certificate for connections whose SNI matches nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertEntry {
    /// SNI names this certificate serves: exact (`api.example.org`) or
    /// single-label wildcard (`*.example.org`). May be empty when `default`.
    #[serde(default)]
    pub sni: Vec<String>,
    /// When `true`, this certificate is served for connections with no
    /// matching SNI (or no SNI at all). At most one entry may be default.
    #[serde(default)]
    pub default: bool,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

/// Fleet-wide TLS policy from the bootstrap node config.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    #[serde(default)]
    pub min_version: MinVersion,
    /// `Strict-Transport-Security` header value injected on HTTPS responses.
    /// Empty disables HSTS injection.
    #[serde(default)]
    pub hsts: String,
    /// Optional file holding fleet-shared TLS session-ticket keys so a
    /// resumed session can land on any node. Absent → per-node keys only.
    #[serde(default)]
    pub ticket_key_file: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_entry_named() {
        let json = r#"{"sni":["a.example.org","*.a.example.org"],"cert_file":"/c.pem","key_file":"/k.pem"}"#;
        let c: CertEntry = serde_json::from_str(json).unwrap();
        assert_eq!(c.sni.len(), 2);
        assert!(!c.default);
    }

    #[test]
    fn cert_entry_default() {
        let json = r#"{"default":true,"cert_file":"/c.pem","key_file":"/k.pem"}"#;
        let c: CertEntry = serde_json::from_str(json).unwrap();
        assert!(c.default);
        assert!(c.sni.is_empty());
    }

    #[test]
    fn min_version_serde() {
        assert_eq!(
            serde_json::from_str::<MinVersion>(r#""1.3""#).unwrap(),
            MinVersion::Tls13
        );
    }
}
