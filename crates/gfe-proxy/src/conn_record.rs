//! Per-connection accounting: what GFE knows about one client connection,
//! reported exactly once, as metrics and as a connection-log event, when the
//! connection is gone.
//!
//! The request-level counterpart is [`crate::record`]. The two are kept
//! apart because their rates and their audiences differ: requests describe
//! what clients asked for, connections describe how clients reach the node
//! (TLS parameters, bytes on the wire, why connections end).

use crate::server::{millis, ServerShared};
use gfe_core::config::Listener;
use gfe_observability::{
    CloseLabels, Counter, ListenerLabel, TlsFailureLabel, TlsLabels, TlsResultLabel,
};
use rustls::{HandshakeKind, ProtocolVersion, ServerConnection};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Close reason of a connection whose task ended without stating one, which
/// only happens when the node shuts down underneath it.
const REASON_SHUTDOWN: &str = "shutdown";

/// The parameters a TLS handshake settled on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInfo {
    /// `TLSv1.2` or `TLSv1.3`.
    pub version: &'static str,
    /// The negotiated cipher suite, e.g. `TLS13_AES_256_GCM_SHA384`.
    pub cipher: String,
    /// The negotiated application protocol, if any (`h2`, `http/1.1`).
    pub alpn: Option<String>,
    /// Whether the session was resumed instead of fully negotiated.
    pub resumed: bool,
}

impl TlsInfo {
    /// Read the negotiated parameters off an established session.
    pub fn of(session: &ServerConnection) -> Self {
        TlsInfo {
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

/// Why a TLS handshake failed, as a bounded label value.
fn tls_failure_reason(error: &io::Error) -> &'static str {
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
        Some(_) => "other",
        None => match error.kind() {
            io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe => "client_closed",
            _ => "io_error",
        },
    }
}

/// Bytes moved over one connection's socket.
#[derive(Debug, Default)]
pub struct Traffic {
    read: AtomicU64,
    written: AtomicU64,
}

/// One client connection, from accept to close.
pub struct ConnRecord {
    shared: Arc<ServerShared>,
    listener: String,
    peer: SocketAddr,
    is_tls: bool,
    opened: Instant,
    traffic: Arc<Traffic>,
    sni: Option<String>,
    tls: Option<TlsInfo>,
    tls_handshake: Option<Duration>,
    tls_error: Option<&'static str>,
    /// How long the connection waited in the accept queue, if known.
    accept_wait: Option<Duration>,
    requests: u64,
    reason: &'static str,
    /// The error that ended the connection, for the log only.
    error: Option<String>,
}

impl ConnRecord {
    /// Start accounting for a connection just accepted on `listener`, whose
    /// socket is bound to `local` on the node's side (if that could be read).
    pub fn open(
        shared: Arc<ServerShared>,
        listener: &Listener,
        local: Option<SocketAddr>,
        peer: SocketAddr,
    ) -> Self {
        let label = ListenerLabel {
            listener: listener.id.to_string(),
        };
        let metrics = &shared.metrics.proxy;
        // Asked first: the answer is "until now".
        let accept_wait = shared
            .accept_queue
            .as_ref()
            .zip(local)
            .and_then(|(queue, local)| queue.waited(local, peer));
        if let Some(waited) = accept_wait {
            metrics
                .accept_queue_wait_seconds
                .get_or_create(&label)
                .observe(waited.as_secs_f64());
        }
        metrics.connections_accepted.get_or_create(&label).inc();
        metrics.connections_active.inc();
        metrics
            .listener_connections_active
            .get_or_create(&label)
            .inc();
        ConnRecord {
            listener: label.listener,
            peer,
            is_tls: listener.is_tls(),
            opened: Instant::now(),
            traffic: Arc::new(Traffic::default()),
            sni: None,
            tls: None,
            tls_handshake: None,
            tls_error: None,
            accept_wait,
            requests: 0,
            reason: REASON_SHUTDOWN,
            error: None,
            shared,
        }
    }

    /// Wrap the connection's socket so the bytes moved over it are counted,
    /// both for this record and in the per-listener byte counters.
    pub fn count_traffic<S>(&self, socket: S) -> CountingIo<S> {
        let label = ListenerLabel {
            listener: self.listener.clone(),
        };
        let metrics = &self.shared.metrics.proxy;
        CountingIo {
            inner: socket,
            traffic: self.traffic.clone(),
            read_total: metrics.bytes_in.get_or_create(&label).clone(),
            written_total: metrics.bytes_out.get_or_create(&label).clone(),
        }
    }

    /// The TLS handshake succeeded after `elapsed`.
    pub fn tls_established(&mut self, tls: TlsInfo, sni: Option<String>, elapsed: Duration) {
        let metrics = &self.shared.metrics.proxy;
        metrics
            .tls_handshakes
            .get_or_create(&TlsResultLabel {
                result: "ok".into(),
            })
            .inc();
        metrics
            .tls_handshake_duration_seconds
            .observe(elapsed.as_secs_f64());
        metrics
            .tls_connections
            .get_or_create(&TlsLabels {
                version: tls.version.to_string(),
                cipher: tls.cipher.clone(),
                alpn: tls.alpn.clone().unwrap_or_else(|| "none".to_string()),
                resumed: tls.resumed.to_string(),
            })
            .inc();
        self.tls = Some(tls);
        self.sni = sni;
        self.tls_handshake = Some(elapsed);
    }

    /// The TLS handshake failed with `error`; the connection is over.
    pub fn tls_failed(&mut self, error: &io::Error) {
        let reason = tls_failure_reason(error);
        let metrics = &self.shared.metrics.proxy;
        metrics
            .tls_handshakes
            .get_or_create(&TlsResultLabel {
                result: "failed".into(),
            })
            .inc();
        metrics
            .tls_handshake_failures
            .get_or_create(&TlsFailureLabel {
                reason: reason.to_string(),
            })
            .inc();
        self.tls_error = Some(reason);
        self.error = Some(error.to_string());
        self.reason = "tls_handshake_failed";
    }

    /// The client did not complete the TLS handshake in time.
    pub fn tls_timed_out(&mut self) {
        self.reason = "tls_handshake_timeout";
    }

    /// The connection ended for `reason` after serving `requests` requests.
    pub fn closed(&mut self, reason: &'static str, requests: u64, error: Option<String>) {
        self.reason = reason;
        self.requests = requests;
        self.error = error;
    }
}

impl Drop for ConnRecord {
    /// Report the connection: the single place it is counted as closed and
    /// logged.
    fn drop(&mut self) {
        let elapsed = self.opened.elapsed();
        let label = ListenerLabel {
            listener: self.listener.clone(),
        };
        let metrics = &self.shared.metrics.proxy;
        metrics.connections_active.dec();
        metrics
            .listener_connections_active
            .get_or_create(&label)
            .dec();
        metrics
            .connections_closed
            .get_or_create(&CloseLabels {
                listener: self.listener.clone(),
                reason: self.reason.to_string(),
            })
            .inc();
        metrics
            .connection_duration_seconds
            .get_or_create(&label)
            .observe(elapsed.as_secs_f64());

        let tls = self.tls.as_ref();
        tracing::info!(
            target: "gfe::conn",
            client = %self.peer.ip(),
            client_port = self.peer.port(),
            listener = %self.listener,
            proto = if self.is_tls { "https" } else { "http" },
            sni = self.sni.as_deref(),
            tls_version = tls.map(|t| t.version),
            tls_cipher = tls.map(|t| t.cipher.as_str()),
            alpn = tls.and_then(|t| t.alpn.as_deref()),
            tls_resumed = tls.map(|t| t.resumed),
            tls_handshake_ms = self.tls_handshake.map(millis),
            tls_error = self.tls_error,
            accept_wait_ms = self.accept_wait.map(millis),
            requests = self.requests,
            bytes_in = self.traffic.read.load(Ordering::Relaxed),
            bytes_out = self.traffic.written.load(Ordering::Relaxed),
            duration_ms = millis(elapsed),
            reason = self.reason,
            error = self.error.as_deref(),
            "connection"
        );
    }
}

/// A socket that counts the bytes read from and written to it. Wrapped
/// around the TCP stream, underneath TLS, so it counts bytes on the wire.
pub struct CountingIo<S> {
    inner: S,
    traffic: Arc<Traffic>,
    read_total: Counter,
    written_total: Counter,
}

impl<S> CountingIo<S> {
    fn count_written(&self, result: &Poll<io::Result<usize>>) {
        if let Poll::Ready(Ok(written)) = result {
            self.traffic
                .written
                .fetch_add(*written as u64, Ordering::Relaxed);
            self.written_total.inc_by(*written as u64);
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let read = (buf.filled().len() - before) as u64;
            self.traffic.read.fetch_add(read, Ordering::Relaxed);
            self.read_total.inc_by(read);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.count_written(&result);
        result
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        self.count_written(&result);
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_cut_short_by_the_client_is_client_closed() {
        let eof = io::Error::new(io::ErrorKind::UnexpectedEof, "tls handshake eof");
        assert_eq!(tls_failure_reason(&eof), "client_closed");
    }

    #[test]
    fn non_tls_bytes_are_an_invalid_message() {
        let error = io::Error::new(
            io::ErrorKind::InvalidData,
            rustls::Error::InvalidMessage(rustls::InvalidMessage::InvalidContentType),
        );
        assert_eq!(tls_failure_reason(&error), "invalid_message");
    }

    #[test]
    fn no_common_parameters_is_peer_incompatible() {
        let error = io::Error::new(
            io::ErrorKind::InvalidData,
            rustls::Error::PeerIncompatible(rustls::PeerIncompatible::NoCipherSuitesInCommon),
        );
        assert_eq!(tls_failure_reason(&error), "peer_incompatible");
    }
}
