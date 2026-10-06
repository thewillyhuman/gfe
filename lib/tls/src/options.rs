//! What a caller tells this crate: the lowest TLS version to accept, and the
//! certificates to serve. Plain data, so that the caller's configuration
//! format stays the caller's: it converts into these where it uses them.
//! Nothing here reads files or validates; [`CertStore::build`] does.
//!
//! [`CertStore::build`]: crate::CertStore::build

use std::path::PathBuf;

/// The oldest TLS version a server accepts. TLS 1.3 is always accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinVersion {
    /// TLS 1.2 and TLS 1.3.
    Tls12,
    /// TLS 1.3 only.
    Tls13,
}

/// A certificate to serve: where its chain and private key are on disk, and
/// which connections get it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertSpec {
    /// The SNI names it serves: exact (`api.example.org`) or a single-label
    /// wildcard (`*.example.org`). May be empty when `default`.
    pub sni: Vec<String>,
    /// Whether it is served to connections whose SNI matches no name, or
    /// that send none. At most one certificate of a store may be default.
    pub default: bool,
    /// PEM file holding the certificate chain, leaf first.
    pub cert_file: PathBuf,
    /// PEM file holding the private key of the leaf.
    pub key_file: PathBuf,
}
