//! The TLS policy every HTTPS listener of a node applies.

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
#[path = "tls_test.rs"]
mod tests;
