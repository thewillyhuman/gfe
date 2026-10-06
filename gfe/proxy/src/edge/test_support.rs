//! What the unit tests of the edge share: certificates and TLS on both
//! ends.

use netkit_tls::{Acceptor, CertSpec, CertStore, MinVersion, SniResolver};
use rustls::pki_types::CertificateDer;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio_rustls::TlsConnector;

/// A self-signed certificate for `name`, written to its own scratch
/// directory and served as the default certificate.
pub(crate) struct TestCert {
    pub(crate) der: CertificateDer<'static>,
    pub(crate) entry: CertSpec,
}

impl TestCert {
    pub(crate) fn new(name: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let cert = rcgen::generate_simple_self_signed(vec![name.to_string()])
            .expect("rcgen signs a valid name");
        let dir = std::env::temp_dir().join(format!(
            "gfe-proxy-edge-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("the temp dir is writable");
        let entry = CertSpec {
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
    let entries: Vec<CertSpec> = certs.iter().map(|cert| cert.entry.clone()).collect();
    let resolver = Arc::new(SniResolver::new(
        CertStore::build(&entries).expect("test certificates load"),
    ));
    let config = netkit_tls::server_config(resolver.clone(), MinVersion::Tls12)
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
