use super::*;

#[test]
fn each_kind_the_client_reports_keeps_its_meaning() {
    let cases = [
        (LibraryKind::ConnectTimeout, FailureKind::ConnectTimeout),
        (LibraryKind::ConnectRefused, FailureKind::ConnectRefused),
        (LibraryKind::ConnectError, FailureKind::ConnectError),
        (LibraryKind::Tls, FailureKind::Tls),
        (LibraryKind::Reset, FailureKind::Reset),
        (LibraryKind::ConnectionLimit, FailureKind::ConnectionLimit),
        (LibraryKind::Other, FailureKind::Other),
    ];
    for (reported, expected) in cases {
        assert_eq!(of(reported, "whatever happened"), expected, "{reported:?}");
    }
}

#[test]
fn a_server_that_did_not_agree_to_speak_http2_is_other() {
    let message = "TLS failure: client error (Connect): TLS handshake with a.example.org: \
                   the server did not agree to speak H2";

    assert_eq!(of(LibraryKind::Tls, message), FailureKind::Other);
}

#[test]
fn a_server_that_refused_every_protocol_offered_is_other() {
    let message = "TLS failure: client error (Connect): TLS handshake with a.example.org: \
                   received fatal alert: NoApplicationProtocol";

    assert_eq!(of(LibraryKind::Tls, message), FailureKind::Other);
}

#[test]
fn an_untrusted_certificate_stays_a_tls_failure() {
    let message = "TLS failure: client error (Connect): TLS handshake with a.example.org: \
                   invalid peer certificate: UnknownIssuer";

    assert_eq!(of(LibraryKind::Tls, message), FailureKind::Tls);
}

#[test]
fn neither_the_connection_limit_nor_a_timeout_is_retryable() {
    assert!(!FailureKind::ConnectionLimit.is_retryable());
    assert!(!FailureKind::Timeout.is_retryable());
    assert!(FailureKind::ConnectRefused.is_retryable());
}

#[test]
fn the_connection_limit_is_not_the_backends_failure() {
    assert!(!FailureKind::ConnectionLimit.is_the_backends());
    assert!(FailureKind::Reset.is_the_backends());
}

#[test]
fn kinds_keep_their_metric_labels_and_log_reasons() {
    let cases = [
        (
            FailureKind::ConnectTimeout,
            "connect_timeout",
            "upstream_connect_timeout",
        ),
        (
            FailureKind::ConnectRefused,
            "connect_refused",
            "upstream_connect_refused",
        ),
        (
            FailureKind::ConnectError,
            "connect_error",
            "upstream_connect_error",
        ),
        (FailureKind::Tls, "tls", "upstream_tls"),
        (FailureKind::Reset, "reset", "upstream_reset"),
        (
            FailureKind::ConnectionLimit,
            "connection_limit",
            "upstream_connection_limit",
        ),
        (FailureKind::Timeout, "timeout", "upstream_timeout"),
        (FailureKind::Other, "other", "upstream_error"),
    ];
    for (kind, label, reason) in cases {
        assert_eq!(kind.as_str(), label, "{kind:?}");
        assert_eq!(kind.reason(), reason, "{kind:?}");
    }
}
