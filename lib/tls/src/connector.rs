//! TLS origination: being the client of a TLS server. Which authorities a
//! server's certificate may be issued by ([`Trust`]), the certificate
//! presented to a server that asks for one ([`Identity`]), and the handshake
//! itself, offering the application protocols the caller wants.
//!
//! What runs over the connection, and how long a handshake may take, is the
//! caller's business: there is no timeout here, and no retry.

use crate::TlsError;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;

/// The client side of a TLS connection, once the handshake is done. Reads
/// and writes plaintext.
pub type ClientTlsStream<IO> = tokio_rustls::client::TlsStream<IO>;

/// An application protocol, as offered and settled on by ALPN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Alpn {
    /// HTTP/1.1 (`http/1.1`).
    Http11,
    /// HTTP/2 (`h2`).
    H2,
}

impl Alpn {
    /// The protocol's ALPN identifier.
    pub fn id(self) -> &'static [u8] {
        match self {
            Alpn::Http11 => b"http/1.1",
            Alpn::H2 => b"h2",
        }
    }

    /// The protocol `id` identifies, if it is one of these.
    pub(crate) fn of(id: &[u8]) -> Option<Alpn> {
        [Alpn::Http11, Alpn::H2]
            .into_iter()
            .find(|alpn| alpn.id() == id)
    }
}

/// Which authorities a server's certificate may be issued by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// The system's trust store.
    System,
    /// The system's trust store and the certificates of this PEM bundle.
    SystemAnd(Vec<u8>),
    /// Nothing is verified: any certificate, for any name, is accepted (the
    /// server must still prove it holds the certificate's key). For checking
    /// that a server answers, never for sending it anything that matters.
    Unverified,
}

/// A certificate chain and its private key, both PEM: the leaf first, then
/// the intermediates, if any.
#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    pub cert_chain_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

impl std::fmt::Debug for Identity {
    // The key stays out of logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity").finish_non_exhaustive()
    }
}

/// What a [`Connector`] is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorOptions {
    /// Who a server's certificate may be issued by.
    pub trust: Trust,
    /// Certificate chain and private key presented to servers that ask
    /// (mTLS); `None` presents nothing.
    pub identity: Option<Identity>,
}

/// TLS towards servers: which authorities are trusted, and who we say we
/// are. Cheap to clone; clones share their session cache, so a connection
/// to a server already spoken to may resume its session.
#[derive(Clone)]
pub struct Connector {
    inner: TlsConnector,
}

impl Connector {
    /// A connector for `options`, using the `ring` crypto provider and the
    /// TLS versions rustls considers safe (1.2 and 1.3).
    ///
    /// Fails, saying which, on a bundle or identity that cannot be used: a
    /// bundle without a certificate, a chain without a certificate, a key
    /// that is missing or of an unsupported type. A system root that does
    /// not parse is skipped with a warning, as is a system store that
    /// cannot be read: what remains is trusted.
    pub fn new(options: ConnectorOptions) -> Result<Connector, TlsError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(TlsError::Policy)?;
        let builder = match options.trust {
            Trust::System => builder.with_root_certificates(system_roots()),
            Trust::SystemAnd(bundle) => {
                let mut roots = system_roots();
                let extra = read_certs(&bundle, "trust bundle")?;
                for cert in extra {
                    roots.add(cert).map_err(|e| {
                        TlsError::InvalidPem(format!("trust bundle: unusable certificate: {e}"))
                    })?;
                }
                builder.with_root_certificates(roots)
            }
            Trust::Unverified => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(Unverified(provider))),
        };
        let config = match options.identity {
            Some(identity) => {
                let chain = read_certs(&identity.cert_chain_pem, "client certificate")?;
                let key = read_key(&identity.key_pem)?;
                builder
                    .with_client_auth_cert(chain, key)
                    .map_err(|e| TlsError::InvalidPem(format!("client identity: {e}")))?
            }
            None => builder.with_no_client_auth(),
        };
        Ok(Connector {
            inner: TlsConnector::from(Arc::new(config)),
        })
    }

    /// Handshake over `io` as the client of `server_name` (a host name or an
    /// IP address, which the server's certificate must name unless the
    /// trust is [`Trust::Unverified`]), offering `alpn` in that order; what
    /// was negotiated comes back with the stream, `None` when the server
    /// chose nothing.
    ///
    /// A failure of TLS itself (an untrusted certificate, no version or
    /// protocol in common, an alert from the server) is an error for which
    /// [`is_tls_error`] holds; any other is the transport's. A
    /// `server_name` that is neither a name nor an address is
    /// `InvalidInput`. There is no timeout: the caller bounds the
    /// handshake.
    pub async fn connect<IO>(
        &self,
        server_name: &str,
        alpn: &[Alpn],
        io: IO,
    ) -> io::Result<(ClientTlsStream<IO>, Option<Alpn>)>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let name = ServerName::try_from(server_name.to_string()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{server_name:?} is not a server name: {e}"),
            )
        })?;
        let offered = alpn.iter().map(|alpn| alpn.id().to_vec()).collect();
        let stream = self.inner.with_alpn(offered).connect(name, io).await?;
        let negotiated = stream.get_ref().1.alpn_protocol().and_then(Alpn::of);
        Ok((stream, negotiated))
    }
}

impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connector").finish_non_exhaustive()
    }
}

/// Whether `error`, as returned by [`Connector::connect`] or by a read or
/// write on the stream it returned, is a failure of TLS itself rather than
/// of the transport under it.
pub fn is_tls_error(error: &io::Error) -> bool {
    // tokio-rustls reports a TLS failure as an `io::Error` wrapping the
    // `rustls::Error`.
    error
        .get_ref()
        .is_some_and(|inner| inner.downcast_ref::<rustls::Error>().is_some())
}

/// The roots of the system's trust store that parse.
fn system_roots() -> RootCertStore {
    let system = rustls_native_certs::load_native_certs();
    for error in &system.errors {
        tracing::warn!(%error, "could not load some system root certificates");
    }
    let mut roots = RootCertStore::empty();
    let (_, skipped) = roots.add_parsable_certificates(system.certs);
    if skipped > 0 {
        tracing::warn!(
            skipped,
            "skipped system root certificates that do not parse"
        );
    }
    roots
}

/// The certificates of `pem`, at least one. `what` names the PEM in errors.
fn read_certs(pem: &[u8], what: &str) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certs = rustls_pemfile::certs(&mut &pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::InvalidPem(format!("{what}: {e}")))?;
    if certs.is_empty() {
        return Err(TlsError::InvalidPem(format!("{what} has no certificate")));
    }
    Ok(certs)
}

/// The first private key of `pem`.
fn read_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, TlsError> {
    match rustls_pemfile::private_key(&mut &pem[..]) {
        Ok(Some(key)) => Ok(key),
        Ok(None) => Err(TlsError::InvalidPem(
            "client identity has no private key".into(),
        )),
        Err(e) => Err(TlsError::InvalidPem(format!("client identity key: {e}"))),
    }
}

/// Accepts any certificate, but still checks, with the provider's own
/// algorithms, that the server signed the handshake with the key of the
/// certificate it presented.
#[derive(Debug)]
struct Unverified(Arc<CryptoProvider>);

impl Unverified {
    fn algorithms(&self) -> &WebPkiSupportedAlgorithms {
        &self.0.signature_verification_algorithms
    }
}

impl ServerCertVerifier for Unverified {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, self.algorithms())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, self.algorithms())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms().supported_schemes()
    }
}

#[cfg(test)]
#[path = "connector_test.rs"]
mod tests;
