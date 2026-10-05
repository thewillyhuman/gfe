//! What the unit tests of the edge share: certificates, TLS on both ends,
//! the shared state, and a connected pair of loopback sockets.

use crate::listener::Shared;
use gfe_config::{CertEntry, LimitsConfig, MinVersion, TimeoutsConfig};
use gfe_observability::GfeMetrics;
use gfe_tls::{Acceptor, CertStore, SniResolver};
use rustls::pki_types::CertificateDer;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

/// A self-signed certificate for `name`, written to its own scratch
/// directory and served as the default certificate.
pub(crate) struct TestCert {
    pub(crate) der: CertificateDer<'static>,
    pub(crate) entry: CertEntry,
}

impl TestCert {
    pub(crate) fn new(name: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let cert = rcgen::generate_simple_self_signed(vec![name.to_string()])
            .expect("rcgen signs a valid name");
        let dir = std::env::temp_dir().join(format!(
            "gfe-core-listener-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("the temp dir is writable");
        let entry = CertEntry {
            sni: vec![name.to_string()],
            default: true,
            cert_file: dir.join("tls.crt"),
            key_file: dir.join("tls.key"),
        };
        std::fs::write(&entry.cert_file, cert.cert.pem()).expect("the temp dir is writable");
        std::fs::write(&entry.key_file, cert.key_pair.serialize_pem())
            .expect("the temp dir is writable");
        TestCert {
            der: cert.cert.der().clone(),
            entry,
        }
    }
}

/// The acceptor serving `certs`, and its resolver.
pub(crate) fn acceptor(certs: &[&TestCert]) -> (Acceptor, Arc<SniResolver>) {
    let entries: Vec<CertEntry> = certs.iter().map(|cert| cert.entry.clone()).collect();
    let resolver = Arc::new(SniResolver::new(
        CertStore::build(&entries).expect("test certificates load"),
    ));
    let config = gfe_tls::server_config(resolver.clone(), MinVersion::Tls12)
        .expect("the default policy is valid");
    (Acceptor::new(Arc::new(config)), resolver)
}

/// A client trusting `certs`, offering ALPN `alpn`.
pub(crate) fn connector(certs: &[&TestCert], alpn: &[&[u8]]) -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert.der.clone())
            .expect("rcgen certificates parse");
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("the default versions are valid")
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    TlsConnector::from(Arc::new(config))
}

/// Shared state with fresh metrics, default limits and `timeouts`.
pub(crate) fn shared(timeouts: TimeoutsConfig) -> Arc<Shared> {
    Arc::new(Shared::new(
        Arc::new(GfeMetrics::new()),
        LimitsConfig::default(),
        timeouts,
    ))
}

/// Both ends of a loopback TCP connection: `(client, server)`.
pub(crate) async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback binds");
    let client = TcpStream::connect(listener.local_addr().expect("bound"))
        .await
        .expect("loopback connects");
    let (server, _) = listener.accept().await.expect("loopback accepts");
    (client, server)
}
