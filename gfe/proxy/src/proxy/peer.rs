//! The peer Pingora connects a request to: where the backend is, how to
//! speak to it (scheme, HTTP version, TLS trust and client certificate) and
//! how long to wait for it.
//!
//! The HTTP version on the upstream leg follows the pool's scheme and the
//! request: HTTP/1.1 for `http`; for `https`, HTTP/1.1 unless the request
//! needs HTTP/2 (gRPC), which ALPN then negotiates; and HTTP/2 with prior
//! knowledge for `h2c`. Over HTTP/1.1 the backend is told the host the
//! client asked for; over HTTP/2 it is named by its own address (see
//! `forward`), which is why requests to `https` pools that do not need
//! HTTP/2 stay on HTTP/1.1.
//!
//! Upstream TLS verifies the certificate and the host name. The trust is
//! the system's roots, plus `[upstream] extra_ca_file` when set. Pingora
//! takes a per-peer CA list that replaces its default roots, so with an
//! extra CA the list holds both, loaded once; it rebuilds its verifier from
//! that list on every new TLS connection (not on a pooled one).

use crate::proxy::error::ProxyError;
use gfe_config::{Scheme, UpstreamConfig};
use pingora_core::protocols::ALPN;
use pingora_core::protocols::tls::CaType;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::utils::tls::{CertKey, WrappedX509};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use x509_parser::prelude::{FromDer, X509Certificate};

/// The most concurrent streams GFE opens on one HTTP/2 connection to a
/// backend before it opens another (a backend's own limit still applies).
const MAX_H2_STREAMS: usize = 100;

/// The connection-pool group of peers that need HTTP/2 from an `https`
/// backend. Pingora does not tell pooled connections apart by the ALPN they
/// were opened with, so without it a gRPC call could be given an HTTP/1.1
/// connection opened for a plain request.
const NEEDS_HTTP2: u64 = 1;

/// The TLS material GFE presents to and trusts backends with, loaded once
/// from the bootstrap config.
#[derive(Clone, Default)]
pub(crate) struct UpstreamTls {
    /// The roots backends' certificates are verified against, when they are
    /// not just the system's; `None` leaves Pingora's own (the system's).
    ca: Option<Arc<CaType>>,
    /// The client certificate presented to backends (mTLS).
    client_cert: Option<Arc<CertKey>>,
}

impl std::fmt::Debug for UpstreamTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamTls")
            .field("ca", &self.ca.as_ref().map(|ca| ca.len()))
            .field("client_cert", &self.client_cert.is_some())
            .finish()
    }
}

impl UpstreamTls {
    /// Load the files `[upstream]` names. Fails fast, naming the file, on
    /// one that cannot be read or holds nothing usable.
    pub(crate) fn load(config: &UpstreamConfig) -> Result<Self, ProxyError> {
        let ca = match &config.extra_ca_file {
            Some(file) => Some(trusted_roots(file)?),
            None => None,
        };
        let client_cert = match (&config.client_cert_file, &config.client_key_file) {
            (Some(cert), Some(key)) => Some(Arc::new(client_certificate(cert, key)?)),
            (None, None) => None,
            _ => return Err(ProxyError::IncompleteClientCertificate),
        };
        Ok(UpstreamTls { ca, client_cert })
    }
}

/// How long to wait for a backend.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Waits {
    /// Establishing a connection (`upstream_connect`), the TLS handshake
    /// included.
    pub(crate) connect: Duration,
    /// For the backend to take or answer the request
    /// (`upstream_first_byte`): bounds every read and write of an attempt.
    pub(crate) first_byte: Duration,
    /// How long a pooled connection may stay idle (`[upstream]
    /// idle_timeout`).
    pub(crate) idle: Duration,
}

/// The peer of one attempt: `backend` (`host`, at `address`) of a pool with
/// `scheme`.
///
/// A gRPC call is not bounded by the read and write timeouts: a stream may
/// be silent for as long as its client lets it. A backend that died is
/// noticed by HTTP/2 pings instead. `read_timeout` is how long the backend
/// may take to answer this attempt.
pub(crate) fn build(
    address: SocketAddr,
    host: &str,
    scheme: Scheme,
    grpc: bool,
    read_timeout: Duration,
    waits: &Waits,
    tls: &UpstreamTls,
) -> HttpPeer {
    let is_tls = scheme == Scheme::Https;
    let mut peer = HttpPeer::new(address, is_tls, host.to_string());
    let options = &mut peer.options;
    options.connection_timeout = Some(waits.connect);
    options.idle_timeout = Some(waits.idle);
    if !grpc {
        options.read_timeout = Some(read_timeout);
        options.write_timeout = Some(waits.first_byte);
    }
    let speaks_http2 = match scheme {
        Scheme::Http => {
            options.alpn = ALPN::H1;
            false
        }
        Scheme::Https if grpc => {
            options.alpn = ALPN::H2H1;
            peer.group_key = NEEDS_HTTP2;
            true
        }
        Scheme::Https => {
            options.alpn = ALPN::H1;
            false
        }
        Scheme::H2c => {
            options.alpn = ALPN::H2;
            true
        }
    };
    if speaks_http2 {
        options.max_h2_streams = MAX_H2_STREAMS;
        options.h2_ping_interval = Some(waits.first_byte);
    }
    if is_tls {
        options.total_connection_timeout = Some(waits.connect);
        options.ca = tls.ca.clone();
        peer.client_cert_key = tls.client_cert.clone();
    }
    peer
}

/// The system's roots and those in `extra_ca_file`.
fn trusted_roots(extra_ca_file: &Path) -> Result<Arc<CaType>, ProxyError> {
    let extra = read_certificates(extra_ca_file, "extra_ca_file")?;
    let system = rustls_native_certs::load_native_certs();
    for error in &system.errors {
        tracing::warn!(%error, "could not load some system root certificates");
    }
    let roots: Vec<WrappedX509> = system
        .certs
        .into_iter()
        .chain(extra)
        .filter_map(|cert| {
            // Pingora's own constructor panics on a certificate it cannot
            // parse: such a root is skipped instead.
            WrappedX509::try_new(cert.to_vec(), |raw| {
                X509Certificate::from_der(raw).map(|(_, cert)| cert)
            })
            .ok()
        })
        .collect();
    Ok(Arc::from(roots))
}

/// The client certificate chain in `cert_file` and its key in `key_file`.
fn client_certificate(cert_file: &Path, key_file: &Path) -> Result<CertKey, ProxyError> {
    let chain = read_certificates(cert_file, "client_cert_file")?;
    let key_error = |reason: String| ProxyError::UpstreamTls {
        setting: "client_key_file",
        file: key_file.to_path_buf(),
        reason,
    };
    let pem = std::fs::read(key_file).map_err(|e| key_error(e.to_string()))?;
    let key = rustls_pemfile::private_key(&mut pem.as_slice())
        .map_err(|e| key_error(e.to_string()))?
        .ok_or_else(|| key_error("no private key".to_string()))?;
    let der = key.secret_der().to_vec();
    // Pingora converts the key back with this, and panics if it fails.
    PrivateKeyDer::try_from(der.clone()).map_err(|e| key_error(e.to_string()))?;
    Ok(CertKey::new(
        chain.into_iter().map(|cert| cert.to_vec()).collect(),
        der,
    ))
}

/// The certificates in a PEM file, at least one.
fn read_certificates(
    file: &Path,
    setting: &'static str,
) -> Result<Vec<CertificateDer<'static>>, ProxyError> {
    let error = |reason: String| ProxyError::UpstreamTls {
        setting,
        file: file.to_path_buf(),
        reason,
    };
    let pem = std::fs::read(file).map_err(|e| error(e.to_string()))?;
    let certs = rustls_pemfile::certs(&mut pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| error(e.to_string()))?;
    if certs.is_empty() {
        return Err(error("no certificate".to_string()));
    }
    Ok(certs)
}

#[cfg(test)]
#[path = "peer_test.rs"]
mod tests;
