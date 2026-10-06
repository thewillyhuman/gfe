//! The TLS handshake on an accepted socket: what it settled on
//! ([`TlsInfo`]) or why it failed ([`HandshakeError`]).

use rustls::{HandshakeKind, ProtocolVersion, ServerConfig, ServerConnection};
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

/// Terminates TLS on accepted sockets with one shared policy (see
/// [`server_config`](crate::server_config)). Cheap to clone.
#[derive(Clone)]
pub struct Acceptor {
    inner: TlsAcceptor,
}

impl Acceptor {
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Acceptor {
            inner: TlsAcceptor::from(config),
        }
    }

    /// Run the server side of the handshake on `io`.
    ///
    /// There is no timeout here: a client that stalls stalls this future, so
    /// the caller bounds it (`[timeouts] tls_handshake`).
    pub async fn accept<IO>(&self, io: IO) -> Result<(TlsStream<IO>, TlsInfo), HandshakeError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let stream = self.inner.accept(io).await.map_err(HandshakeError)?;
        let info = TlsInfo::of(stream.get_ref().1);
        Ok((stream, info))
    }
}

impl std::fmt::Debug for Acceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Acceptor").finish_non_exhaustive()
    }
}

/// The parameters a TLS handshake settled on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInfo {
    /// The server name the client asked for, lowercased; `None` without SNI.
    pub sni: Option<String>,
    /// `TLSv1.2` or `TLSv1.3`.
    pub version: &'static str,
    /// The negotiated cipher suite, e.g. `TLS13_AES_256_GCM_SHA384`.
    pub cipher: String,
    /// The negotiated application protocol (`h2`, `http/1.1`), if any.
    pub alpn: Option<String>,
    /// Whether the session was resumed instead of fully negotiated.
    pub resumed: bool,
}

impl TlsInfo {
    /// Read the negotiated parameters off an established session. The
    /// `unknown` fallbacks cannot happen once a handshake has completed.
    pub(crate) fn of(session: &ServerConnection) -> Self {
        TlsInfo {
            // rustls already lowercases it; done again so that the contract
            // does not rest on that.
            sni: session.server_name().map(str::to_ascii_lowercase),
            version: match session.protocol_version() {
                Some(ProtocolVersion::TLSv1_3) => "TLSv1.3",
                Some(ProtocolVersion::TLSv1_2) => "TLSv1.2",
                _ => "unknown",
            },
            cipher: session
                .negotiated_cipher_suite()
                .map(|suite| format!("{:?}", suite.suite()))
                .unwrap_or_else(|| "unknown".to_string()),
            alpn: session
                .alpn_protocol()
                .map(|protocol| String::from_utf8_lossy(protocol).into_owned()),
            resumed: matches!(session.handshake_kind(), Some(HandshakeKind::Resumed)),
        }
    }
}

/// A handshake that failed. Displays as the underlying error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct HandshakeError(io::Error);

impl HandshakeError {
    /// Why the handshake failed, as a bounded label value:
    /// `invalid_message`, `peer_incompatible`, `alert_received`,
    /// `peer_misbehaved`, `client_closed`, `io_error` or `other`.
    pub fn reason(&self) -> &'static str {
        failure_reason(&self.0)
    }
}

/// See [`HandshakeError::reason`]. tokio-rustls reports a TLS-level failure
/// as an `io::Error` wrapping the `rustls::Error`, and a transport failure as
/// a bare `io::Error`.
fn failure_reason(error: &io::Error) -> &'static str {
    let tls_error = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>());
    match tls_error {
        // Not TLS at all (typically plain HTTP sent to an HTTPS port) or a
        // corrupted record.
        Some(rustls::Error::InvalidMessage(_)) => "invalid_message",
        // No protocol version, cipher suite or key exchange in common.
        Some(rustls::Error::PeerIncompatible(_)) => "peer_incompatible",
        // The client aborted, e.g. because it does not trust the certificate.
        Some(rustls::Error::AlertReceived(_)) => "alert_received",
        Some(rustls::Error::PeerMisbehaved(_)) => "peer_misbehaved",
        // Includes no certificate for the requested name.
        Some(_) => "other",
        None => match error.kind() {
            io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe => "client_closed",
            _ => "io_error",
        },
    }
}

#[cfg(test)]
#[path = "acceptor_test.rs"]
mod tests;
