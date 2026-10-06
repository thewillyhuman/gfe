//! The kernel's view of the node's TCP connections (`netkit-kernel`), turned into
//! what the rest of the node already speaks: an answer to the edge's
//! accept-queue question, metrics, and one `gfe::tcp` log event per closed
//! connection.
//!
//! Every node attempts to attach it. A node that cannot (not Linux, not the
//! capabilities, an old kernel) logs why at error level, leaves
//! `gfe_ebpf_attached` at 0 for an alert to see, and serves without it:
//! observability failing must not become an availability failure.

use crate::edge::{AcceptQueue, Listeners, RequestHandler};
use crate::metrics::{
    BackendLabel, ClientEndingLabels, GfeMetrics, KernelMetrics, ListenerLabel,
    UpstreamEndingLabels,
};
use gfe_config::NodeConfig;
use netkit_kernel::{ClosedConnection, ClosedConnections, Ending, Origin, TcpProbe};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// The attached kernel program, as the edge and the ops endpoint use it.
pub struct KernelView {
    probe: TcpProbe,
}

impl std::fmt::Debug for KernelView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KernelView").finish_non_exhaustive()
    }
}

impl KernelView {
    /// Closed connections the kernel could not report because the reader
    /// fell behind.
    pub fn lost_events(&self) -> u64 {
        self.probe.lost_events()
    }
}

impl AcceptQueue for KernelView {
    fn waited(&self, local: SocketAddr, peer: SocketAddr) -> Option<Duration> {
        self.probe.accept_queue_wait(local, peer)
    }
}

/// Attach the kernel program, sized for the connections `node` may have
/// open. `None` if it cannot be attached: that is logged with the reason at
/// error level and never fatal. `gfe_ebpf_attached` says which it is.
pub fn attach(
    node: &NodeConfig,
    metrics: &GfeMetrics,
) -> Option<(Arc<KernelView>, ClosedConnections)> {
    // The program keeps a record per open connection, client and upstream.
    let connections = node
        .limits
        .max_connections
        .saturating_add(node.limits.max_upstream_connections);
    match TcpProbe::attach(u32::try_from(connections).unwrap_or(u32::MAX)) {
        Ok((probe, closed)) => {
            metrics.kernel.ebpf_attached.set(1);
            tracing::info!(
                connections,
                "kernel view of tcp connections attached (eBPF)"
            );
            Some((Arc::new(KernelView { probe }), closed))
        }
        Err(reason) => {
            metrics.kernel.ebpf_attached.set(0);
            tracing::error!(
                %reason,
                "kernel view of tcp connections unavailable (eBPF not attached); \
                 serving without the gfe_*_tcp_* metrics and gfe::tcp events"
            );
            None
        }
    }
}

/// Report every connection the kernel says has closed, until `closed` ends
/// or the task is aborted. A client connection is reported under the
/// listener of `listeners` it was accepted on.
pub async fn report<H: RequestHandler>(
    mut closed: ClosedConnections,
    listeners: Arc<Listeners<H>>,
    metrics: Arc<GfeMetrics>,
) {
    while let Some(connection) = closed.next().await {
        let listener = match connection.origin {
            Origin::Accepted => listeners.listener_at(connection.local),
            Origin::Connected => None,
        };
        record(
            &metrics.kernel,
            &connection,
            listener.map(|id| id.to_string()),
        );
    }
}

fn ending_label(ending: Ending) -> &'static str {
    match ending {
        Ending::PeerClosed => "peer_closed",
        Ending::NodeClosed => "node_closed",
        Ending::Aborted => "aborted",
        Ending::Other => "other",
    }
}

fn millis(duration: Duration) -> f64 {
    duration.as_micros() as f64 / 1000.0
}

/// Count and log one closed connection. `listener` is the proxy listener an
/// accepted connection came in on.
///
/// Connections accepted on anything else (the ops endpoint being scraped)
/// are not client traffic and are left out.
fn record(metrics: &KernelMetrics, closed: &ClosedConnection, listener: Option<String>) {
    let ending = ending_label(closed.ending);
    match (closed.origin, listener) {
        (Origin::Accepted, None) => {}
        (Origin::Accepted, Some(listener)) => {
            let label = ListenerLabel {
                listener: listener.clone(),
            };
            metrics
                .client_tcp_rtt_seconds
                .get_or_create(&label)
                .observe(closed.rtt.as_secs_f64());
            metrics
                .client_tcp_segments_sent
                .get_or_create(&label)
                .inc_by(closed.segments_sent.into());
            metrics
                .client_tcp_retransmits
                .get_or_create(&label)
                .inc_by(closed.retransmits.into());
            metrics
                .client_tcp_closes
                .get_or_create(&ClientEndingLabels {
                    listener: listener.clone(),
                    ending: ending.to_string(),
                })
                .inc();
            // `client` and `client_port` are the ones of the `gfe::conn`
            // event of the same connection.
            tracing::info!(
                target: "gfe::tcp",
                side = "client",
                client = %closed.peer.ip(),
                client_port = closed.peer.port(),
                listener = %listener,
                ending,
                rtt_ms = millis(closed.rtt),
                min_rtt_ms = millis(closed.min_rtt),
                retransmits = closed.retransmits,
                segments_sent = closed.segments_sent,
                bytes_acked = closed.bytes_acked,
                bytes_received = closed.bytes_received,
                lifetime_ms = millis(closed.lifetime),
                "tcp connection"
            );
        }
        (Origin::Connected, _) => {
            let backend = closed.peer.to_string();
            let label = BackendLabel {
                backend: backend.clone(),
            };
            metrics
                .upstream_tcp_rtt_seconds
                .get_or_create(&label)
                .observe(closed.rtt.as_secs_f64());
            metrics
                .upstream_tcp_segments_sent
                .get_or_create(&label)
                .inc_by(closed.segments_sent.into());
            metrics
                .upstream_tcp_retransmits
                .get_or_create(&label)
                .inc_by(closed.retransmits.into());
            metrics
                .upstream_tcp_closes
                .get_or_create(&UpstreamEndingLabels {
                    backend: backend.clone(),
                    ending: ending.to_string(),
                })
                .inc();
            tracing::info!(
                target: "gfe::tcp",
                side = "upstream",
                backend = %backend,
                ending,
                rtt_ms = millis(closed.rtt),
                min_rtt_ms = millis(closed.min_rtt),
                retransmits = closed.retransmits,
                segments_sent = closed.segments_sent,
                bytes_acked = closed.bytes_acked,
                bytes_received = closed.bytes_received,
                lifetime_ms = millis(closed.lifetime),
                "tcp connection"
            );
        }
    }
}

#[cfg(test)]
#[path = "kernel_test.rs"]
mod tests;
