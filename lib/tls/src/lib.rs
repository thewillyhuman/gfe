//! TLS in both directions, on rustls.
//!
//! **Terminating** it, for the clients of a server: which certificate a
//! client gets (by SNI, from a store swapped atomically when certificates
//! change), the policy every listener applies (versions, ALPN, session
//! resumption), the handshake itself and what it settled on or why it
//! failed ([`Acceptor`]), and noticing that certificate files were replaced
//! on disk ([`CertFiles`]).
//!
//! **Originating** it, towards a server ([`Connector`]): which authorities
//! are trusted (the system's trust store, with more added, or nothing
//! verified at all for a check that only asks whether a server answers),
//! and the certificate presented to servers that ask for one.
//!
//! The crate is plain rustls / tokio-rustls: it knows nothing about HTTP and
//! records no metric. Callers turn what it returns ([`TlsInfo`],
//! [`HandshakeError::reason`], [`SniResolver::miss_count`],
//! [`CertStore::expiries`]) into metrics and logs.

mod acceptor;
mod cert_files;
mod cert_store;
mod connector;
mod error;
mod loader;
mod options;
mod policy;
mod resolver;
#[cfg(test)]
mod test_support;

pub use acceptor::{Acceptor, HandshakeError, TlsInfo};
pub use cert_files::CertFiles;
pub use cert_store::CertStore;
pub use connector::{
    Alpn, ClientTlsStream, Connector, ConnectorOptions, Identity, Trust, is_protocol_refusal,
    is_tls_error,
};
pub use error::TlsError;
pub use loader::{LoadedCert, load_cert_files, load_cert_pem};
pub use options::{CertSpec, MinVersion};
pub use policy::{ALPN_PROTOCOLS, server_config};
pub use resolver::SniResolver;
