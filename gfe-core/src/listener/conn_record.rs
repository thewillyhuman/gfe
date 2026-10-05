//! Per-connection accounting: what the node knows about one client
//! connection, reported exactly once, as metrics and as a `gfe::conn` event,
//! when the connection is gone.
//!
//! The request-level counterpart is whoever answers the requests. The two are
//! kept apart because their rates and their audiences differ: requests
//! describe what clients asked for, connections describe how clients reach
//! the node (TLS parameters, bytes on the wire, why connections end).
//!
//! Pingora does not say why it stopped serving a connection, so the reason
//! is derived ([`close_reason`]) from what the edge observes: the
//! handshake, how the client's side ended, what the edge did itself, whether
//! the node was draining, and the requests the connection carried.

use crate::listener::activity::Expiry;
use crate::listener::stream::{Metered, StreamState, WireEnd};
use crate::listener::{ConnInfo, Shared};
use gfe_config::Listener;
use gfe_observability::{
    CloseLabels, ListenerLabel, RejectLabel, TlsFailureLabel, TlsLabels, TlsResultLabel,
};
use gfe_tls::{HandshakeError, TlsInfo};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How the TLS handshake of a connection went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Handshake {
    /// None was needed (plaintext), or it succeeded.
    Done,
    Failed,
    TimedOut,
}

/// What the edge observed about a connection that has ended, from which
/// its close reason is derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Observed {
    pub(crate) handshake: Handshake,
    /// Whether the application finished with the connection. `false` when
    /// the connection's task was cancelled (the drain deadline) or panicked.
    pub(crate) served: bool,
    pub(crate) panicked: bool,
    /// Why the edge ended the connection, or asked it to end, if it did.
    pub(crate) expiry: Option<Expiry>,
    /// How the client's side ended, if the stream saw it.
    pub(crate) end: Option<WireEnd>,
    pub(crate) draining: bool,
    pub(crate) requests: u64,
    pub(crate) in_flight: bool,
}

/// Why a connection ended, as a bounded label value
/// (`gfe_connections_closed_total{reason}` and the `gfe::conn` event).
///
/// Where the observations cannot tell two reasons apart, the more general
/// one is given; a precise reason is never guessed:
///
/// - `closed` also covers the application ending the connection after a
///   response on its own (`Connection: close`, an HTTP/1.0 client, a
///   keep-alive limit or timeout of its own) and a client that left between
///   requests, whatever it had sent of the next one.
/// - `protocol_error` is any connection the application gave up before a
///   single request reached it: a malformed request head (answered `400` by
///   Pingora), a broken HTTP/2 preface, or a request it refused before
///   looking it up.
/// - `error` is also any connection the application gave up with a request
///   still in flight.
pub(crate) fn close_reason(observed: &Observed) -> &'static str {
    match observed.handshake {
        Handshake::Failed => return "tls_handshake_failed",
        Handshake::TimedOut => return "tls_handshake_timeout",
        Handshake::Done => {}
    }
    if !observed.served {
        return if observed.panicked {
            "error"
        } else {
            "shutdown"
        };
    }
    match observed.expiry {
        Some(Expiry::Header) => return "header_timeout",
        Some(Expiry::Idle) => return "idle_timeout",
        Some(Expiry::Drain) => return "drain",
        None => {}
    }
    match observed.end {
        Some(WireEnd::Reset) => "client_abort",
        Some(WireEnd::TimedOut) => "client_unresponsive",
        Some(WireEnd::Error) => "error",
        Some(WireEnd::Eof) if observed.in_flight => "client_abort",
        // The application stopped on its own, the client still there.
        None if observed.in_flight => "error",
        _ if observed.draining => "drain",
        Some(WireEnd::Eof) => "closed",
        None if observed.requests == 0 => "protocol_error",
        None => "closed",
    }
}

/// One client connection, from accept to close. Reports it when dropped:
/// whatever ends the connection's task (the connection closing, the task
/// being cancelled at the drain deadline, a panic) accounts for it exactly
/// once.
pub(crate) struct ConnRecord {
    shared: Arc<Shared>,
    listener: String,
    client: SocketAddr,
    is_tls: bool,
    opened: Instant,
    stream: Arc<StreamState>,
    handshake: Handshake,
    tls: Option<TlsInfo>,
    tls_handshake: Option<Duration>,
    tls_error: Option<&'static str>,
    /// Why the handshake failed, for the log only.
    error: Option<String>,
    /// How long the connection waited in the accept queue, if known.
    accept_wait: Option<Duration>,
    /// The connection as registered for its requests, once it is.
    conn: Option<Arc<ConnInfo>>,
    served: bool,
}

impl ConnRecord {
    /// Start accounting for a connection from `client` just accepted on
    /// `listener`, whose socket is bound to `local` on the node's side.
    pub(crate) fn open(
        shared: Arc<Shared>,
        listener: &Listener,
        local: SocketAddr,
        client: SocketAddr,
    ) -> Self {
        let label = ListenerLabel {
            listener: listener.id.to_string(),
        };
        let metrics = &shared.metrics().proxy;
        // Asked first: the answer is "until now".
        let accept_wait = shared.accept_wait(local, client);
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
            client,
            is_tls: listener.is_tls(),
            opened: Instant::now(),
            stream: Arc::new(StreamState::default()),
            handshake: Handshake::Done,
            tls: None,
            tls_handshake: None,
            tls_error: None,
            error: None,
            accept_wait,
            conn: None,
            served: false,
            shared,
        }
    }

    /// Wrap the connection's socket so the bytes moved over it are counted,
    /// both for this record and in the listener's byte counters, and so
    /// that how it ends is noted.
    pub(crate) fn meter<S>(&self, socket: S) -> Metered<S> {
        let label = ListenerLabel {
            listener: self.listener.clone(),
        };
        let metrics = &self.shared.metrics().proxy;
        Metered::new(
            socket,
            Arc::clone(&self.stream),
            metrics.bytes_in.get_or_create(&label).clone(),
            metrics.bytes_out.get_or_create(&label).clone(),
        )
    }

    /// What the connection's stream observed.
    pub(crate) fn stream(&self) -> &Arc<StreamState> {
        &self.stream
    }

    /// The TLS handshake negotiated `tls` after `elapsed`.
    pub(crate) fn tls_established(&mut self, tls: &TlsInfo, elapsed: Duration) {
        let metrics = &self.shared.metrics().proxy;
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
        self.tls = Some(tls.clone());
        self.tls_handshake = Some(elapsed);
    }

    /// The TLS handshake failed with `error`; the connection is over.
    pub(crate) fn tls_failed(&mut self, error: &HandshakeError) {
        let reason = error.reason();
        let metrics = &self.shared.metrics().proxy;
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
        self.handshake = Handshake::Failed;
        self.tls_error = Some(reason);
        self.error = Some(error.to_string());
    }

    /// The client did not complete the TLS handshake in time; the
    /// connection is over.
    pub(crate) fn tls_timed_out(&mut self) {
        self.shared
            .metrics()
            .proxy
            .connections_rejected
            .get_or_create(&RejectLabel {
                reason: "handshake_timeout".into(),
            })
            .inc();
        self.handshake = Handshake::TimedOut;
    }

    /// The connection is registered as `conn` and handed to the application.
    pub(crate) fn serving(&mut self, conn: Arc<ConnInfo>) {
        self.conn = Some(conn);
    }

    /// The application is done with the connection.
    pub(crate) fn served(&mut self) {
        self.served = true;
    }

    fn observed(&self) -> Observed {
        Observed {
            handshake: self.handshake,
            served: self.served,
            panicked: std::thread::panicking(),
            expiry: self.stream.expiry(),
            end: self.stream.end(),
            draining: self.shared.is_draining(),
            requests: self.conn.as_ref().map_or(0, |conn| conn.requests()),
            in_flight: self
                .conn
                .as_ref()
                .is_some_and(|conn| conn.has_request_in_flight()),
        }
    }
}

/// A duration in milliseconds, with microsecond resolution.
fn millis(duration: Duration) -> f64 {
    duration.as_micros() as f64 / 1000.0
}

impl Drop for ConnRecord {
    fn drop(&mut self) {
        let observed = self.observed();
        let reason = close_reason(&observed);
        let elapsed = self.opened.elapsed();
        let label = ListenerLabel {
            listener: self.listener.clone(),
        };
        let metrics = &self.shared.metrics().proxy;
        metrics.connections_active.dec();
        metrics
            .listener_connections_active
            .get_or_create(&label)
            .dec();
        metrics
            .connections_closed
            .get_or_create(&CloseLabels {
                listener: self.listener.clone(),
                reason: reason.to_string(),
            })
            .inc();
        metrics
            .connection_duration_seconds
            .get_or_create(&label)
            .observe(elapsed.as_secs_f64());

        let tls = self.tls.as_ref();
        let error = self.error.as_deref().or_else(|| self.stream.error());
        tracing::info!(
            target: "gfe::conn",
            client = %self.client.ip(),
            client_port = self.client.port(),
            listener = %self.listener,
            proto = if self.is_tls { "https" } else { "http" },
            sni = tls.and_then(|t| t.sni.as_deref()),
            tls_version = tls.map(|t| t.version),
            tls_cipher = tls.map(|t| t.cipher.as_str()),
            alpn = tls.and_then(|t| t.alpn.as_deref()),
            tls_resumed = tls.map(|t| t.resumed),
            tls_handshake_ms = self.tls_handshake.map(millis),
            tls_error = self.tls_error,
            accept_wait_ms = self.accept_wait.map(millis),
            requests = observed.requests,
            bytes_in = self.stream.bytes_in(),
            bytes_out = self.stream.bytes_out(),
            duration_ms = millis(elapsed),
            reason,
            error,
            "connection"
        );
    }
}

#[cfg(test)]
#[path = "conn_record_test.rs"]
mod tests;
