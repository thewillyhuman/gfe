//! Certificates: which certificate a TLS listener serves for which name.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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

#[cfg(test)]
#[path = "certificate_test.rs"]
mod tests;
