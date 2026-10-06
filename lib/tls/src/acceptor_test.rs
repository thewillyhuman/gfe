//! How failures are labelled. Handshakes themselves are tested end to end in
//! `tests/acceptor.rs`.

use super::*;

fn tls_error(error: rustls::Error) -> HandshakeError {
    HandshakeError(io::Error::new(io::ErrorKind::InvalidData, error))
}

#[test]
fn a_handshake_cut_short_by_the_client_is_client_closed() {
    let eof = io::Error::new(io::ErrorKind::UnexpectedEof, "tls handshake eof");

    assert_eq!(HandshakeError(eof).reason(), "client_closed");
}

#[test]
fn a_reset_connection_is_client_closed() {
    let reset = io::Error::from(io::ErrorKind::ConnectionReset);

    assert_eq!(HandshakeError(reset).reason(), "client_closed");
}

#[test]
fn another_transport_failure_is_an_io_error() {
    let refused = io::Error::from(io::ErrorKind::PermissionDenied);

    assert_eq!(HandshakeError(refused).reason(), "io_error");
}

#[test]
fn non_tls_bytes_are_an_invalid_message() {
    let error = tls_error(rustls::Error::InvalidMessage(
        rustls::InvalidMessage::InvalidContentType,
    ));

    assert_eq!(error.reason(), "invalid_message");
}

#[test]
fn no_common_parameters_is_peer_incompatible() {
    let error = tls_error(rustls::Error::PeerIncompatible(
        rustls::PeerIncompatible::NoCipherSuitesInCommon,
    ));

    assert_eq!(error.reason(), "peer_incompatible");
}

#[test]
fn an_alert_from_the_client_is_alert_received() {
    let error = tls_error(rustls::Error::AlertReceived(
        rustls::AlertDescription::BadCertificate,
    ));

    assert_eq!(error.reason(), "alert_received");
}

#[test]
fn a_protocol_violation_is_peer_misbehaved() {
    let error = tls_error(rustls::Error::PeerMisbehaved(
        rustls::PeerMisbehaved::TooManyEmptyFragments,
    ));

    assert_eq!(error.reason(), "peer_misbehaved");
}

#[test]
fn any_other_tls_error_is_other() {
    let error = tls_error(rustls::Error::General("no certificate".into()));

    assert_eq!(error.reason(), "other");
}

#[test]
fn displays_the_underlying_error() {
    let error = tls_error(rustls::Error::General("no certificate".into()));

    assert!(error.to_string().contains("no certificate"), "{error}");
}
