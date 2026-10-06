//! Per-connection accounting: what the node knows about one client
//! connection, reported exactly once, as metrics and as a `gfe::conn` event,
//! when the connection is gone.
//!
//! The request-level counterpart is whoever answers the requests. The two
//! are kept apart because their rates and their audiences differ: requests
//! describe what clients asked for, connections describe how clients reach
//! the node (TLS parameters, bytes on the wire, why connections end).
//!
//! Why a connection ended is what `netkit_http` says it did ([`Closed`]),
//! what the TLS handshake did before that, or, for a connection whose
//! serving was dropped before it ended, `shutdown`. This module only turns
//! those into GFE's label values; it does not observe the connection.

use crate::edge::Shared;
use crate::metrics::{
    CloseLabels, ListenerLabel, RejectLabel, TlsFailureLabel, TlsLabels, TlsResultLabel,
};
use gfe_config::Listener;
use netkit_http::server::{CloseReason, Closed};
use netkit_listen::{Meter, Metered};
use netkit_tls::{HandshakeError, TlsInfo};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The label value of a connection served over HTTP that ended for
/// `reason` (`gfe_connections_closed_total{reason}` and the `gfe::conn`
/// event).
pub(crate) fn close_reason(reason: CloseReason) -> &'static str {
    match reason {
        CloseReason::Closed => "closed",
        CloseReason::Drain => "drain",
        CloseReason::IdleTimeout => "idle_timeout",
        CloseReason::HeaderTimeout => "header_timeout",
        CloseReason::ClientAbort => "client_abort",
        CloseReason::ClientUnresponsive => "client_unresponsive",
        CloseReason::ProtocolError => "protocol_error",
        CloseReason::Error => "error",
    }
}

/// The address as the node reports it: an IPv4 client of a dual-stack
/// socket is `1.2.3.4`, not `::ffff:1.2.3.4`, as in the kernel view.
fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

/// A duration in milliseconds, with microsecond resolution.
fn millis(duration: Duration) -> f64 {
    duration.as_micros() as f64 / 1000.0
}

/// One client connection, from accept to close. Reports it when dropped:
/// whatever ends the connection's task (the connection closing, the task
/// being dropped at the drain deadline, a panic) accounts for it exactly
/// once.
pub(crate) struct ConnRecord {
    shared: Arc<Shared>,
    listener: String,
    client: SocketAddr,
    is_tls: bool,
    opened: Instant,
    /// The bytes on the wire, once the stream is metered.
    meter: Option<Meter>,
    tls: Option<TlsInfo>,
    tls_handshake: Option<Duration>,
    tls_error: Option<&'static str>,
    /// How long the connection waited in the accept queue, if known.
    accept_wait: Option<Duration>,
    requests: u64,
    /// Why the connection ended, once that is known. A record dropped
    /// without one was cut short.
    reason: Option<&'static str>,
    /// The error that ended the connection, for the log only.
    error: Option<String>,
}

impl ConnRecord {
    /// Start accounting for a connection from `client` just accepted on
    /// `listener` (as configured now), whose socket is bound to `local` on
    /// the node's side.
    pub(crate) fn open(
        shared: Arc<Shared>,
        listener: &Listener,
        local: SocketAddr,
        client: SocketAddr,
    ) -> Self {
        let client = canonical(client);
        let label = ListenerLabel {
            listener: listener.id.to_string(),
        };
        let metrics = &shared.metrics().proxy;
        // Asked first: the answer is "until now".
        let accept_wait = shared.accept_wait(canonical(local), client);
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
            meter: None,
            tls: None,
            tls_handshake: None,
            tls_error: None,
            accept_wait,
            requests: 0,
            reason: None,
            error: None,
            shared,
        }
    }

    /// Wrap the connection's socket so that the bytes moved over it are
    /// counted, for this record and, when it is reported, in the
    /// listener's byte counters.
    pub(crate) fn meter<S>(&mut self, socket: S) -> Metered<S> {
        let metered = Metered::new(socket);
        self.meter = Some(metered.meter());
        metered
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
        self.tls_error = Some(reason);
        self.error = Some(error.to_string());
        self.reason = Some("tls_handshake_failed");
    }

    /// The client did not complete the TLS handshake in time; the
    /// connection is over. Also counted as a rejected connection.
    pub(crate) fn tls_timed_out(&mut self) {
        self.shared
            .metrics()
            .proxy
            .connections_rejected
            .get_or_create(&RejectLabel {
                reason: "handshake_timeout".into(),
            })
            .inc();
        self.reason = Some("tls_handshake_timeout");
    }

    /// The connection was served over HTTP and ended as `closed` says.
    pub(crate) fn closed(&mut self, closed: &Closed) {
        self.reason = Some(close_reason(closed.reason));
        self.requests = closed.requests;
        self.error.clone_from(&closed.error);
    }
}

impl Drop for ConnRecord {
    /// Report the connection: the single place it is counted as closed and
    /// logged.
    fn drop(&mut self) {
        let reason = self.reason.unwrap_or(if std::thread::panicking() {
            "error"
        } else {
            "shutdown"
        });
        let elapsed = self.opened.elapsed();
        let (bytes_in, bytes_out) = self
            .meter
            .as_ref()
            .map_or((0, 0), |meter| (meter.bytes_read(), meter.bytes_written()));
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
        metrics.bytes_in.get_or_create(&label).inc_by(bytes_in);
        metrics.bytes_out.get_or_create(&label).inc_by(bytes_out);

        let tls = self.tls.as_ref();
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
            requests = self.requests,
            bytes_in,
            bytes_out,
            duration_ms = millis(elapsed),
            reason,
            error = self.error.as_deref(),
            "connection"
        );
    }
}

#[cfg(test)]
#[path = "conn_record_test.rs"]
mod tests;
