//! `Connector` end to end, in process: the connector and a rustls server
//! talk over an in-memory duplex pipe, with certificates issued by a private
//! CA that `rcgen` makes for each test.

use netkit_tls::{Alpn, Connector, ConnectorOptions, Identity, Trust, is_tls_error};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio_rustls::TlsAcceptor;

/// A certificate authority that issues certificates for the test.
struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl Ca {
    fn new() -> Ca {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        Ca { cert, key }
    }

    fn pem(&self) -> Vec<u8> {
        self.cert.pem().into_bytes()
    }

    fn der(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }

    /// A certificate for `names` with its key, signed by this authority.
    fn issue(&self, names: &[&str], usage: ExtendedKeyUsagePurpose) -> Issued {
        let names: Vec<String> = names.iter().map(|name| name.to_string()).collect();
        let mut params = CertificateParams::new(names).unwrap();
        params.extended_key_usages = vec![usage];
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.cert, &self.key).unwrap();
        Issued { cert, key }
    }
}

struct Issued {
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl Issued {
    fn der(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }

    fn key_der(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.serialize_der()))
    }

    fn identity(&self) -> Identity {
        Identity {
            cert_chain_pem: self.cert.pem().into_bytes(),
            key_pem: self.key.serialize_pem().into_bytes(),
        }
    }
}

/// How the server side of a test is set up.
struct Server {
    cert: Issued,
    alpn: Vec<&'static [u8]>,
    /// The authority client certificates must be issued by; `None` asks for
    /// none.
    client_ca: Option<CertificateDer<'static>>,
}

impl Server {
    fn new(cert: Issued) -> Server {
        Server {
            cert,
            alpn: Vec::new(),
            client_ca: None,
        }
    }

    fn acceptor(&self) -> TlsAcceptor {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap();
        let builder = match &self.client_ca {
            Some(ca) => {
                let mut roots = rustls::RootCertStore::empty();
                roots.add(ca.clone()).unwrap();
                let verifier = WebPkiClientVerifier::builder_with_provider(roots.into(), provider)
                    .build()
                    .unwrap();
                builder.with_client_cert_verifier(verifier)
            }
            None => builder.with_no_client_auth(),
        };
        let mut config = builder
            .with_single_cert(vec![self.cert.der()], self.cert.key_der())
            .unwrap();
        config.alpn_protocols = self.alpn.iter().map(|id| id.to_vec()).collect();
        TlsAcceptor::from(Arc::new(config))
    }
}

/// What the server saw of a completed handshake.
struct Seen {
    client_certificate: Option<CertificateDer<'static>>,
}

/// Run a handshake between `connector` (as the client of `server_name`,
/// offering `alpn`) and `server`, then send one byte each way.
async fn handshake(
    connector: &Connector,
    server_name: &str,
    alpn: &[Alpn],
    server: &Server,
) -> (io::Result<Option<Alpn>>, Option<Seen>) {
    let (client_io, server_io) = duplex(64 * 1024);
    let acceptor = server.acceptor();
    let server_side = tokio::spawn(async move {
        let mut stream = acceptor.accept(server_io).await.ok()?;
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.ok()?;
        stream.write_all(&byte).await.ok()?;
        stream.flush().await.ok()?;
        let client_certificate = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first().cloned());
        Some(Seen { client_certificate })
    });

    let client_side = async {
        let (mut stream, negotiated) = connector.connect(server_name, alpn, client_io).await?;
        stream.write_all(b"x").await?;
        stream.flush().await?;
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        Ok(negotiated)
    };
    let client = client_side.await;
    let seen = server_side.await.unwrap();
    (client, seen)
}

fn connector(trust: Trust, identity: Option<Identity>) -> Connector {
    Connector::new(ConnectorOptions { trust, identity }).unwrap()
}

#[tokio::test]
async fn the_system_store_alone_refuses_a_private_authority() {
    let ca = Ca::new();
    let server = Server::new(ca.issue(&["server.test"], ExtendedKeyUsagePurpose::ServerAuth));
    let connector = connector(Trust::System, None);

    let (client, _) = handshake(&connector, "server.test", &[], &server).await;

    let error = client.unwrap_err();
    assert!(is_tls_error(&error), "{error}");
}

#[tokio::test]
async fn an_extra_bundle_makes_a_private_authority_trusted() {
    let ca = Ca::new();
    let server = Server::new(ca.issue(&["server.test"], ExtendedKeyUsagePurpose::ServerAuth));
    let connector = connector(Trust::SystemAnd(ca.pem()), None);

    let (client, seen) = handshake(&connector, "server.test", &[], &server).await;

    assert!(client.is_ok(), "{:?}", client.err());
    assert!(seen.is_some());
}

#[tokio::test]
async fn a_certificate_for_another_name_is_refused() {
    let ca = Ca::new();
    let server = Server::new(ca.issue(&["other.test"], ExtendedKeyUsagePurpose::ServerAuth));
    let connector = connector(Trust::SystemAnd(ca.pem()), None);

    let (client, _) = handshake(&connector, "server.test", &[], &server).await;

    let error = client.unwrap_err();
    assert!(is_tls_error(&error), "{error}");
}

#[tokio::test]
async fn unverified_accepts_any_certificate() {
    let ca = Ca::new();
    let server = Server::new(ca.issue(&["other.test"], ExtendedKeyUsagePurpose::ServerAuth));
    let connector = connector(Trust::Unverified, None);

    let (client, _) = handshake(&connector, "server.test", &[], &server).await;

    assert!(client.is_ok(), "{:?}", client.err());
}

#[tokio::test]
async fn an_ip_address_is_verified_against_the_certificate() {
    let ca = Ca::new();
    let server = Server::new(ca.issue(&["127.0.0.1"], ExtendedKeyUsagePurpose::ServerAuth));
    let connector = connector(Trust::SystemAnd(ca.pem()), None);

    let (client, _) = handshake(&connector, "127.0.0.1", &[], &server).await;

    assert!(client.is_ok(), "{:?}", client.err());
}

#[tokio::test]
async fn presents_the_identity_to_a_server_that_asks() {
    let ca = Ca::new();
    let client_cert = ca.issue(&["client.test"], ExtendedKeyUsagePurpose::ClientAuth);
    let mut server = Server::new(ca.issue(&["server.test"], ExtendedKeyUsagePurpose::ServerAuth));
    server.client_ca = Some(ca.der());
    let connector = connector(Trust::SystemAnd(ca.pem()), Some(client_cert.identity()));

    let (client, seen) = handshake(&connector, "server.test", &[], &server).await;

    assert!(client.is_ok(), "{:?}", client.err());
    let presented = seen.unwrap().client_certificate;
    assert_eq!(presented, Some(client_cert.der()));
}

#[tokio::test]
async fn without_an_identity_a_server_that_requires_one_refuses() {
    let ca = Ca::new();
    let mut server = Server::new(ca.issue(&["server.test"], ExtendedKeyUsagePurpose::ServerAuth));
    server.client_ca = Some(ca.der());
    let connector = connector(Trust::SystemAnd(ca.pem()), None);

    let (client, seen) = handshake(&connector, "server.test", &[], &server).await;

    // With TLS 1.3 the client learns of the refusal on its first read.
    let error = client.unwrap_err();
    assert!(is_tls_error(&error), "{error}");
    assert!(seen.is_none());
}

#[tokio::test]
async fn negotiates_the_first_offered_protocol_the_server_speaks() {
    let ca = Ca::new();
    let mut server = Server::new(ca.issue(&["server.test"], ExtendedKeyUsagePurpose::ServerAuth));
    server.alpn = vec![b"h2", b"http/1.1"];
    let connector = connector(Trust::SystemAnd(ca.pem()), None);

    let (h2, _) = handshake(
        &connector,
        "server.test",
        &[Alpn::H2, Alpn::Http11],
        &server,
    )
    .await;
    let (http11, _) = handshake(&connector, "server.test", &[Alpn::Http11], &server).await;

    assert_eq!(h2.unwrap(), Some(Alpn::H2));
    assert_eq!(http11.unwrap(), Some(Alpn::Http11));
}

#[tokio::test]
async fn nothing_is_negotiated_with_a_server_without_alpn() {
    let ca = Ca::new();
    let server = Server::new(ca.issue(&["server.test"], ExtendedKeyUsagePurpose::ServerAuth));
    let connector = connector(Trust::SystemAnd(ca.pem()), None);

    let (client, _) = handshake(&connector, "server.test", &[Alpn::H2], &server).await;

    assert_eq!(client.unwrap(), None);
}

#[tokio::test]
async fn a_server_with_no_protocol_in_common_refuses() {
    let ca = Ca::new();
    let mut server = Server::new(ca.issue(&["server.test"], ExtendedKeyUsagePurpose::ServerAuth));
    server.alpn = vec![b"http/1.1"];
    let connector = connector(Trust::SystemAnd(ca.pem()), None);

    let (client, _) = handshake(&connector, "server.test", &[Alpn::H2], &server).await;

    let error = client.unwrap_err();
    assert!(is_tls_error(&error), "{error}");
}

#[tokio::test]
async fn a_server_that_hangs_up_is_a_transport_failure() {
    let connector = connector(Trust::Unverified, None);
    let (client_io, server_io) = duplex(1024);
    drop(server_io);

    let error = connector
        .connect("server.test", &[], client_io)
        .await
        .err()
        .unwrap();

    assert!(!is_tls_error(&error), "{error}");
}

#[tokio::test]
async fn refuses_a_server_name_that_is_not_one() {
    let connector = connector(Trust::Unverified, None);
    let (client_io, _server_io) = duplex(1024);

    let error = connector
        .connect("not a name", &[], client_io)
        .await
        .err()
        .unwrap();

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{error}");
}
