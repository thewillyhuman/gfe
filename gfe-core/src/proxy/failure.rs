//! Why a request to a backend failed before any response arrived, told
//! apart from a client that went away or stalled while it was sent.
//!
//! Pingora reports every failure as one [`Error`]: its type says what broke
//! and its source which side broke it. This module turns that into the
//! bounded set of kinds GFE counts and logs.

use pingora_error::{Error, ErrorSource, ErrorType};

/// The error type a connection refused at `max_upstream_connections` is
/// reported with (see `connection_cap`).
pub(crate) const CONNECTION_LIMIT: ErrorType = ErrorType::Custom("UpstreamConnectionLimit");

/// The kinds of upstream failure GFE tells apart. A bounded set, so it can
/// label a metric (`gfe_upstream_errors_total{kind}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailureKind {
    /// The backend did not answer the TCP handshake within `upstream_connect`.
    ConnectTimeout,
    /// The backend refused the TCP connection: nothing listens on the port.
    ConnectRefused,
    /// The connection could not be established for another reason (no route,
    /// name resolution, ...).
    ConnectError,
    /// The TLS handshake with the backend failed, e.g. an untrusted
    /// certificate.
    Tls,
    /// The connection to the backend broke before it responded: closed,
    /// reset, or no longer answering HTTP/2 pings.
    Reset,
    /// The node already holds as many upstream connections as it may
    /// (`max_upstream_connections`), so none was opened for this request.
    ConnectionLimit,
    /// The backend did not start responding within `upstream_first_byte`
    /// of having last been sent something, or stopped taking the request.
    Timeout,
    /// Anything else.
    Other,
}

impl FailureKind {
    /// The `kind` label of `gfe_upstream_errors_total`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            FailureKind::ConnectTimeout => "connect_timeout",
            FailureKind::ConnectRefused => "connect_refused",
            FailureKind::ConnectError => "connect_error",
            FailureKind::Tls => "tls",
            FailureKind::Reset => "reset",
            FailureKind::ConnectionLimit => "connection_limit",
            FailureKind::Timeout => "timeout",
            FailureKind::Other => "other",
        }
    }

    /// The access-log `error` of a request that failed this way.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            FailureKind::ConnectTimeout => "upstream_connect_timeout",
            FailureKind::ConnectRefused => "upstream_connect_refused",
            FailureKind::ConnectError => "upstream_connect_error",
            FailureKind::Tls => "upstream_tls",
            FailureKind::Reset => "upstream_reset",
            FailureKind::ConnectionLimit => "upstream_connection_limit",
            FailureKind::Timeout => "upstream_timeout",
            FailureKind::Other => "upstream_error",
        }
    }

    /// Whether the failure is the backend's: what the node itself refused
    /// (its connection limit) is not counted against the backend.
    pub(crate) fn is_the_backends(self) -> bool {
        self != FailureKind::ConnectionLimit
    }

    /// Whether another attempt could fare better. A node-wide limit is not
    /// something another backend fixes, and a backend that timed out has
    /// already used up the time the request had.
    pub(crate) fn is_retryable(self) -> bool {
        !matches!(self, FailureKind::ConnectionLimit | FailureKind::Timeout)
    }
}

/// Who a failed exchange is to blame on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The backend, or the way to it.
    Upstream(FailureKind),
    /// The client stopped sending the request body: answered `408`, and the
    /// backend is not counted as failing.
    ClientStalled,
    /// The client went away: there is nobody left to answer.
    ClientGone,
}

/// Classify `error`, which ended an exchange before any response arrived.
///
/// `connecting` says whether it happened while establishing the connection
/// (`fail_to_connect`) rather than on an established one. `request_complete`
/// says whether the client had sent its whole request: a backend that times
/// out while the client still owes it part of the body is waiting for the
/// client, which is the client's stall, not the backend's. (A backend that
/// stops taking the body fails the write instead, and that is its own.)
pub(crate) fn classify(error: &Error, connecting: bool, request_complete: bool) -> Failure {
    let etype = error.etype();
    if *error.esource() == ErrorSource::Downstream {
        return match etype {
            ErrorType::ReadTimedout => Failure::ClientStalled,
            _ => Failure::ClientGone,
        };
    }
    let kind = match etype {
        _ if *etype == CONNECTION_LIMIT => FailureKind::ConnectionLimit,
        ErrorType::ConnectTimedout => FailureKind::ConnectTimeout,
        ErrorType::ConnectRefused => FailureKind::ConnectRefused,
        ErrorType::TLSHandshakeFailure
        | ErrorType::TLSHandshakeTimedout
        | ErrorType::TLSWantX509Lookup
        | ErrorType::InvalidCert
        | ErrorType::HandshakeError => FailureKind::Tls,
        _ if connecting => FailureKind::ConnectError,
        ErrorType::ReadTimedout if !request_complete => return Failure::ClientStalled,
        ErrorType::ReadTimedout | ErrorType::WriteTimedout => FailureKind::Timeout,
        ErrorType::ConnectionClosed
        | ErrorType::ReadError
        | ErrorType::WriteError
        | ErrorType::H2Error => FailureKind::Reset,
        _ => FailureKind::Other,
    };
    Failure::Upstream(kind)
}

#[cfg(test)]
#[path = "failure_test.rs"]
mod tests;
