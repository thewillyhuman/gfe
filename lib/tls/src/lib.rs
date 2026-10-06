//! TLS termination for client connections: which certificate a client gets
//! (by SNI, from a store swapped atomically on reload), the TLS policy every
//! HTTPS listener applies (versions, ALPN, session resumption), the handshake
//! itself and what it settled on or why it failed, and noticing that the
//! certificate files were replaced on disk.
//!
//! The crate is plain rustls / tokio-rustls: it knows nothing about HTTP nor
//! about the proxy engine, and records no metric. Callers turn what it
//! returns ([`TlsInfo`], [`HandshakeError::reason`],
//! [`SniResolver::miss_count`], [`CertStore::expiries`]) into metrics and
//! logs.

mod acceptor;
mod cert_files;
mod cert_store;
mod connector;
mod error;
mod loader;
mod policy;
mod resolver;
#[cfg(test)]
mod test_support;

pub use acceptor::{Acceptor, HandshakeError, TlsInfo};
pub use cert_files::CertFiles;
pub use cert_store::CertStore;
pub use connector::{
    Alpn, ClientTlsStream, Connector, ConnectorOptions, Identity, Trust, is_tls_error,
};
pub use error::TlsError;
pub use loader::{LoadedCert, load_cert_files, load_cert_pem};
pub use policy::{ALPN_PROTOCOLS, server_config};
pub use resolver::SniResolver;
