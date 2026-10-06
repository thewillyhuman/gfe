//! How errors are classified. Each kind is also reached end to end, from a
//! real exchange, in `tests/client_failures.rs`.

use super::*;
use netkit_rate_limiting::LimitReached;
use std::net::SocketAddr;
use std::time::Duration;

fn tcp(kind: io::ErrorKind) -> ConnectError {
    ConnectError::Tcp {
        address: SocketAddr::from(([127, 0, 0, 1], 80)),
        source: io::Error::from(kind),
    }
}

fn tls(source: io::Error) -> ConnectError {
    ConnectError::Tls {
        server_name: "server.test".into(),
        source,
    }
}

/// The kind of a failure to connect with `error`.
fn connecting(error: ConnectError) -> FailureKind {
    Failure::new(Box::new(error), true).kind()
}

#[test]
fn the_cap_is_a_connection_limit() {
    let error = ConnectError::Limit(LimitReached { max: 1 });

    assert_eq!(connecting(error), FailureKind::ConnectionLimit);
}

#[test]
fn a_connect_deadline_is_a_connect_timeout() {
    let error = ConnectError::TimedOut {
        host: "server.test".into(),
        port: 80,
        after: Duration::from_millis(50),
    };

    assert_eq!(connecting(error), FailureKind::ConnectTimeout);
}

#[test]
fn the_systems_own_connect_timeout_is_a_connect_timeout() {
    assert_eq!(
        connecting(tcp(io::ErrorKind::TimedOut)),
        FailureKind::ConnectTimeout
    );
}

#[test]
fn a_refused_connection_is_connect_refused() {
    assert_eq!(
        connecting(tcp(io::ErrorKind::ConnectionRefused)),
        FailureKind::ConnectRefused
    );
}

#[test]
fn another_tcp_failure_is_a_connect_error() {
    assert_eq!(
        connecting(tcp(io::ErrorKind::HostUnreachable)),
        FailureKind::ConnectError
    );
}

#[test]
fn a_failed_lookup_is_a_connect_error() {
    let error = ConnectError::Resolve {
        host: "server.test".into(),
        port: 80,
        source: io::Error::other("no such host"),
    };

    assert_eq!(connecting(error), FailureKind::ConnectError);
}

#[test]
fn a_failure_of_tls_itself_is_tls() {
    let refused = io::Error::new(
        io::ErrorKind::InvalidData,
        rustls::Error::General("bad certificate".into()),
    );

    assert_eq!(connecting(tls(refused)), FailureKind::Tls);
}

#[test]
fn a_transport_failure_during_the_handshake_is_a_connect_error() {
    let closed = io::Error::from(io::ErrorKind::UnexpectedEof);

    assert_eq!(connecting(tls(closed)), FailureKind::ConnectError);
}

#[test]
fn a_protocol_the_server_does_not_choose_is_a_refused_protocol() {
    let error = ConnectError::Alpn {
        server_name: "server.test".into(),
        offered: netkit_tls::Alpn::H2,
    };

    assert_eq!(connecting(error), FailureKind::ProtocolRefused);
}

#[test]
fn the_alert_of_a_server_with_no_protocol_in_common_is_a_refused_protocol() {
    let alert = io::Error::new(
        io::ErrorKind::InvalidData,
        rustls::Error::AlertReceived(rustls::AlertDescription::NoApplicationProtocol),
    );

    assert_eq!(connecting(tls(alert)), FailureKind::ProtocolRefused);
}

#[test]
fn a_reset_once_connected_is_a_reset() {
    let error = io::Error::from(io::ErrorKind::ConnectionReset);

    assert_eq!(FailureKind::of(&error, false), FailureKind::Reset);
}

#[test]
fn a_tls_alert_once_connected_is_tls() {
    let error = io::Error::new(
        io::ErrorKind::InvalidData,
        rustls::Error::AlertReceived(rustls::AlertDescription::CertificateRequired),
    );

    assert_eq!(FailureKind::of(&error, false), FailureKind::Tls);
}

#[test]
fn an_unrecognised_error_once_connected_is_other() {
    let error = io::Error::other("something else");

    assert_eq!(FailureKind::of(&error, false), FailureKind::Other);
}

#[test]
fn displays_the_kind_and_every_cause() {
    let failure = Failure::new(Box::new(tcp(io::ErrorKind::ConnectionRefused)), true);

    assert_eq!(
        failure.to_string(),
        "connection refused: connecting to 127.0.0.1:80: connection refused"
    );
}

#[test]
fn keeps_the_original_error_as_its_source() {
    let failure = Failure::new(Box::new(tcp(io::ErrorKind::ConnectionRefused)), true);

    let source = std::error::Error::source(&failure).unwrap();

    assert!(source.downcast_ref::<ConnectError>().is_some());
}

#[test]
fn a_caller_error_is_other() {
    let error = http::Uri::builder()
        .authority("not an authority")
        .build()
        .unwrap_err();

    assert_eq!(Failure::other(error).kind(), FailureKind::Other);
}
