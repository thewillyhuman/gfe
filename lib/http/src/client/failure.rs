//! Why an exchange with a server failed, sorted into the few kinds a caller
//! acts on differently (retry elsewhere, answer with one status or another,
//! count). The kinds say what happened, not what to do about it.

use super::dial::ConnectError;
use crate::body::BoxError;
use std::error::Error;
use std::fmt;
use std::io;

/// The kinds of failure told apart. A closed set: a caller matches on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureKind {
    /// No connection was open within the connect timeout (the lookup, TCP
    /// and TLS together), or the operating system gave up on the TCP
    /// handshake.
    ConnectTimeout,
    /// The server refused the TCP connection: nothing listens on the port.
    ConnectRefused,
    /// The connection could not be established for another reason: the
    /// name did not resolve, no route, the server hung up during the TLS
    /// handshake.
    ConnectError,
    /// TLS failed: the server's certificate is not trusted or does not name
    /// it, the server refused the client's certificate, no version in
    /// common.
    Tls,
    /// The server would not speak the protocol the request needs: offered
    /// that protocol alone, it chose none, or answered that it has none in
    /// common. A request that needs HTTP/2, sent to a server that only
    /// speaks HTTP/1.1, fails this way.
    ProtocolRefused,
    /// The connection broke before the response head arrived: closed,
    /// reset, or no longer answering HTTP/2 keep-alive pings.
    Reset,
    /// As many connections are open as the cap allows, so none was opened
    /// for this request.
    ConnectionLimit,
    /// Anything else, such as a request that could not be sent as given.
    Other,
}

impl FailureKind {
    /// Classify the error a failed exchange ended with, walking its chain of
    /// sources. `connecting` says whether it failed while opening the
    /// connection.
    pub(crate) fn of(error: &(dyn Error + 'static), connecting: bool) -> FailureKind {
        let mut cause = Some(error);
        while let Some(current) = cause {
            if let Some(connect) = current.downcast_ref::<ConnectError>() {
                return FailureKind::of_connect(connect);
            }
            if let Some(io) = current.downcast_ref::<io::Error>() {
                if netkit_tls::is_tls_error(io) {
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
                        return FailureKind::Reset;
                    }
                    _ => {}
                }
            }
            if let Some(http) = current.downcast_ref::<hyper::Error>() {
                // The caller's own request body failed: not the server's
                // doing, whatever the body's error says.
                if http.is_user() {
                    return FailureKind::Other;
                }
                // Once connected, the only timer on a connection is the
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

    fn of_connect(error: &ConnectError) -> FailureKind {
        match error {
            ConnectError::Limit(_) => FailureKind::ConnectionLimit,
            ConnectError::TimedOut { .. } => FailureKind::ConnectTimeout,
            ConnectError::Resolve { .. } => FailureKind::ConnectError,
            ConnectError::Tcp { source, .. } => match source.kind() {
                io::ErrorKind::ConnectionRefused => FailureKind::ConnectRefused,
                io::ErrorKind::TimedOut => FailureKind::ConnectTimeout,
                _ => FailureKind::ConnectError,
            },
            ConnectError::Tls { source, .. } if netkit_tls::is_protocol_refusal(source) => {
                FailureKind::ProtocolRefused
            }
            ConnectError::Tls { source, .. } if netkit_tls::is_tls_error(source) => {
                FailureKind::Tls
            }
            ConnectError::Tls { .. } => FailureKind::ConnectError,
            ConnectError::Alpn { .. } => FailureKind::ProtocolRefused,
        }
    }
}

impl fmt::Display for FailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            FailureKind::ConnectTimeout => "connect timeout",
            FailureKind::ConnectRefused => "connection refused",
            FailureKind::ConnectError => "connect error",
            FailureKind::Tls => "TLS failure",
            FailureKind::ProtocolRefused => "protocol refused",
            FailureKind::Reset => "connection reset",
            FailureKind::ConnectionLimit => "connection limit reached",
            FailureKind::Other => "request failed",
        })
    }
}

/// Why an exchange failed before the response head arrived: its kind, and
/// the error it ended with as [`source`](Error::source). Displays as the
/// kind followed by every cause, so that the message alone says what
/// happened.
#[derive(Debug)]
pub struct Failure {
    kind: FailureKind,
    source: BoxError,
}

impl Failure {
    /// A failure ending with `source`; `connecting` says whether it happened
    /// while opening the connection.
    pub(crate) fn new(source: BoxError, connecting: bool) -> Failure {
        Failure {
            kind: FailureKind::of(source.as_ref(), connecting),
            source,
        }
    }

    /// A failure that is not the server's doing: the request could not be
    /// sent as given.
    pub(crate) fn other(source: impl Into<BoxError>) -> Failure {
        Failure {
            kind: FailureKind::Other,
            source: source.into(),
        }
    }

    /// What kind of failure this is.
    pub fn kind(&self) -> FailureKind {
        self.kind
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.source)?;
        // hyper's own messages are terse ("client error (Connect)"); the
        // causes underneath are what tell an operator what happened.
        let mut cause = self.source.source();
        while let Some(current) = cause {
            write!(f, ": {current}")?;
            cause = current.source();
        }
        Ok(())
    }
}

impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[cfg(test)]
#[path = "failure_test.rs"]
mod tests;
