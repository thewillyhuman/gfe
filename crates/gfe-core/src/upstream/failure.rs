//! Why an upstream request failed before any response arrived.

use crate::upstream::client::BoxError;
use crate::upstream::limit::ConnectionLimitReached;
use std::error::Error;
use std::fmt;
use std::io;

/// The kinds of upstream failure GFE tells apart. A bounded set, so it can
/// label a metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
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
    /// reset, or no longer answering HTTP/2 keep-alive pings.
    Reset,
    /// The node already holds as many upstream connections as it may
    /// (`max_upstream_connections`), so none was opened for this request.
    ConnectionLimit,
    /// Anything else.
    Other,
}

impl FailureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FailureKind::ConnectTimeout => "connect_timeout",
            FailureKind::ConnectRefused => "connect_refused",
            FailureKind::ConnectError => "connect_error",
            FailureKind::Tls => "tls",
            FailureKind::Reset => "reset",
            FailureKind::ConnectionLimit => "connection_limit",
            FailureKind::Other => "other",
        }
    }

    /// Classify the error a failed request ended with. `connecting` says
    /// whether it failed while establishing the connection.
    fn of(error: &(dyn Error + 'static), connecting: bool) -> FailureKind {
        let mut cause = Some(error);
        while let Some(current) = cause {
            if current.downcast_ref::<ConnectionLimitReached>().is_some() {
                return FailureKind::ConnectionLimit;
            }
            if current.downcast_ref::<rustls::Error>().is_some() {
                return FailureKind::Tls;
            }
            if let Some(io) = current.downcast_ref::<io::Error>() {
                let wraps_tls = io
                    .get_ref()
                    .is_some_and(|inner| inner.downcast_ref::<rustls::Error>().is_some());
                if wraps_tls {
                    return FailureKind::Tls;
                }
                match io.kind() {
                    io::ErrorKind::TimedOut if connecting => return FailureKind::ConnectTimeout,
                    io::ErrorKind::ConnectionRefused => return FailureKind::ConnectRefused,
                    io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
                        if !connecting =>
                    {
                        return FailureKind::Reset
                    }
                    _ => {}
                }
            }
            if let Some(http) = current.downcast_ref::<hyper::Error>() {
                // Once connected, the only timer on the client is the
                // HTTP/2 keep-alive: a timeout is a peer that went silent.
                let died = !connecting && http.is_timeout();
                if died || http.is_incomplete_message() || http.is_canceled() || http.is_closed() {
                    return FailureKind::Reset;
                }
            }
            cause = current.source();
        }
        if connecting {
            FailureKind::ConnectError
        } else {
            FailureKind::Other
        }
    }
}

/// A request that failed before any response, with what kind of failure it
/// was.
#[derive(Debug)]
pub struct UpstreamFailure {
    pub kind: FailureKind,
    source: BoxError,
}

impl UpstreamFailure {
    /// A failure of the upstream client itself.
    pub(crate) fn from_client(error: hyper_util::client::legacy::Error) -> Self {
        UpstreamFailure {
            kind: FailureKind::of(&error, error.is_connect()),
            source: Box::new(error),
        }
    }

    /// A failure that is not the backend's doing.
    pub(crate) fn other(source: BoxError) -> Self {
        UpstreamFailure {
            kind: FailureKind::Other,
            source,
        }
    }
}

impl fmt::Display for UpstreamFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.as_str(), self.source)?;
        // The client's own message is terse ("client error (Connect)"); the
        // cause underneath is what tells an operator what happened.
        let mut cause = self.source.source();
        while let Some(current) = cause {
            write!(f, ": {current}")?;
            cause = current.source();
        }
        Ok(())
    }
}

impl Error for UpstreamFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_while_connecting_is_a_connect_timeout() {
        let error = io::Error::new(io::ErrorKind::TimedOut, "deadline elapsed");
        assert_eq!(FailureKind::of(&error, true), FailureKind::ConnectTimeout);
    }

    #[test]
    fn refused_connection_is_connect_refused() {
        let error = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert_eq!(FailureKind::of(&error, true), FailureKind::ConnectRefused);
    }

    #[test]
    fn tls_error_wrapped_in_io_error_is_tls() {
        let error = io::Error::new(
            io::ErrorKind::InvalidData,
            rustls::Error::General("bad certificate".into()),
        );
        assert_eq!(FailureKind::of(&error, true), FailureKind::Tls);
    }

    #[test]
    fn reset_on_an_established_connection_is_a_reset() {
        let error = io::Error::from(io::ErrorKind::ConnectionReset);
        assert_eq!(FailureKind::of(&error, false), FailureKind::Reset);
    }

    #[test]
    fn unrecognised_connect_failure_is_a_connect_error() {
        let error = io::Error::other("no route to host");
        assert_eq!(FailureKind::of(&error, true), FailureKind::ConnectError);
    }
}
