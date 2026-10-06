//! Why an attempt against a backend failed, in GFE's words: the bounded set
//! of kinds that label `gfe_upstream_errors_total{kind}`, name the access
//! log's `error`, and decide the answer and whether to retry.
//!
//! The client reports what broke ([`netkit_http::client::FailureKind`]);
//! this module adds the one kind it cannot see, a backend that took too
//! long ([`FailureKind::Timeout`]: how long a backend may take is GFE's
//! business, not the client's), and maps the rest as the hyper-based
//! release (`v1.1.0`) did. What is done about a failure is decided
//! elsewhere: the answer in `respond`, a retry in `retry`.

use netkit_http::client::{Failure, FailureKind as LibraryKind};

/// What the client says when a server would not speak HTTP/2 after it was
/// offered nothing else: the server chose no protocol, or chose another.
const DID_NOT_AGREE: &str = "did not agree to speak";

/// The TLS alert of a server that supports none of the protocols offered.
const NO_APPLICATION_PROTOCOL: &str = "NoApplicationProtocol";

/// The kinds of upstream failure GFE tells apart. A bounded set, so it can
/// label a metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailureKind {
    /// No connection to the backend within `upstream_connect`.
    ConnectTimeout,
    /// The backend refused the TCP connection: nothing listens on the port.
    ConnectRefused,
    /// The connection could not be established for another reason (no
    /// route, name resolution, ...).
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
    /// of having last been sent something, or within `request_total`.
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

    /// The access log's `error` for a request that failed this way.
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

/// The kind of `failure`, which ended an exchange before any response head
/// arrived.
pub(crate) fn classify(failure: &Failure) -> FailureKind {
    of(failure.kind(), &failure.to_string())
}

/// The kind of a failure the client reported as `reported`, described by
/// `message` (the failure with all its causes).
///
/// A request that needs HTTP/2, sent to an `https` backend that will not
/// speak it, is a TLS failure to the client, which offers HTTP/2 alone.
/// `v1.1.0` offered both protocols, was answered over HTTP/1.1 and failed
/// the request as `other`; operators' dashboards know it so. The client
/// tells that case apart only in its message, hence the text match.
fn of(reported: LibraryKind, message: &str) -> FailureKind {
    match reported {
        LibraryKind::ConnectTimeout => FailureKind::ConnectTimeout,
        LibraryKind::ConnectRefused => FailureKind::ConnectRefused,
        LibraryKind::ConnectError => FailureKind::ConnectError,
        LibraryKind::Tls
            if message.contains(DID_NOT_AGREE) || message.contains(NO_APPLICATION_PROTOCOL) =>
        {
            FailureKind::Other
        }
        LibraryKind::Tls => FailureKind::Tls,
        LibraryKind::Reset => FailureKind::Reset,
        LibraryKind::ConnectionLimit => FailureKind::ConnectionLimit,
        LibraryKind::Other => FailureKind::Other,
    }
}

#[cfg(test)]
#[path = "failure_test.rs"]
mod tests;
