//! What a `Connector` accepts to be built from, and how failures read.
//! Handshakes themselves are tested end to end in `tests/connector.rs`.

use super::*;
use crate::test_support::self_signed;

fn options(trust: Trust, identity: Option<Identity>) -> ConnectorOptions {
    ConnectorOptions { trust, identity }
}

#[test]
fn builds_on_the_system_trust_store() {
    assert!(Connector::new(options(Trust::System, None)).is_ok());
}

#[test]
fn builds_with_an_extra_bundle_and_an_identity() {
    let (ca, _) = self_signed(&["ca.test"]);
    let (cert, key) = self_signed(&["client.test"]);

    let connector = Connector::new(options(
        Trust::SystemAnd(ca),
        Some(Identity {
            cert_chain_pem: cert,
            key_pem: key,
        }),
    ));

    assert!(connector.is_ok());
}

#[test]
fn refuses_a_bundle_without_a_certificate() {
    let error = Connector::new(options(Trust::SystemAnd(b"not pem".to_vec()), None)).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("trust bundle has no certificate"),
        "{error}"
    );
}

#[test]
fn refuses_an_identity_without_a_key() {
    let (cert, _) = self_signed(&["client.test"]);

    let error = Connector::new(options(
        Trust::Unverified,
        Some(Identity {
            cert_chain_pem: cert.clone(),
            key_pem: cert,
        }),
    ))
    .unwrap_err();

    assert!(error.to_string().contains("no private key"), "{error}");
}

#[test]
fn refuses_an_identity_without_a_certificate() {
    let (_, key) = self_signed(&["client.test"]);

    let error = Connector::new(options(
        Trust::Unverified,
        Some(Identity {
            cert_chain_pem: key.clone(),
            key_pem: key,
        }),
    ))
    .unwrap_err();

    assert!(error.to_string().contains("no certificate"), "{error}");
}

#[test]
fn names_each_protocol_as_alpn_does() {
    assert_eq!(Alpn::H2.id(), b"h2");
    assert_eq!(Alpn::Http11.id(), b"http/1.1");
    assert_eq!(Alpn::of(b"h2"), Some(Alpn::H2));
    assert_eq!(Alpn::of(b"http/1.1"), Some(Alpn::Http11));
    assert_eq!(Alpn::of(b"spdy/3"), None);
}

#[test]
fn a_failure_of_tls_itself_is_a_tls_error() {
    let error = io::Error::new(
        io::ErrorKind::InvalidData,
        rustls::Error::General("bad certificate".into()),
    );

    assert!(is_tls_error(&error));
}

#[test]
fn a_transport_failure_is_not_a_tls_error() {
    let error = io::Error::from(io::ErrorKind::UnexpectedEof);

    assert!(!is_tls_error(&error));
}

#[test]
fn invalid_data_from_elsewhere_is_not_a_tls_error() {
    let error = io::Error::new(io::ErrorKind::InvalidData, "not tls");

    assert!(!is_tls_error(&error));
}
