//! The kernel's view of the node's TCP connections, as the eBPF program
//! reports it when a connection closes: round-trip time, segments sent and
//! retransmitted, and how the connection ended, per listener on the client
//! side and per backend address on the upstream side.

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;

use crate::ListenerLabel;

/// `backend` label: the address of the other end of an upstream connection,
/// as the kernel sees it (`ip:port`).
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BackendLabel {
    pub backend: String,
}

/// Labels for closed client connections. `ending` is how the connection
/// ended: `peer_closed`, `node_closed`, `aborted` or `other`.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ClientEndingLabels {
    pub listener: String,
    pub ending: String,
}

/// Labels for closed upstream connections; `ending` as in
/// [`ClientEndingLabels`].
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct UpstreamEndingLabels {
    pub backend: String,
    pub ending: String,
}

/// What the kernel reports about the node's TCP connections (eBPF). Every
/// node attempts to attach the kernel program; all of this stays at zero
/// while it is not attached.
#[derive(Clone)]
pub struct KernelMetrics {
    /// 1 while the kernel program is attached, 0 otherwise. A node that
    /// could not attach it serves without it; an alert watches for the 0.
    pub ebpf_attached: Gauge,
    /// Closed connections the kernel could not report because the reader
    /// fell behind.
    pub ebpf_lost_events: Gauge,
    pub client_tcp_rtt_seconds: Family<ListenerLabel, Histogram>,
    pub client_tcp_segments_sent: Family<ListenerLabel, Counter>,
    pub client_tcp_retransmits: Family<ListenerLabel, Counter>,
    pub client_tcp_closes: Family<ClientEndingLabels, Counter>,
    pub upstream_tcp_rtt_seconds: Family<BackendLabel, Histogram>,
    pub upstream_tcp_segments_sent: Family<BackendLabel, Counter>,
    pub upstream_tcp_retransmits: Family<BackendLabel, Counter>,
    pub upstream_tcp_closes: Family<UpstreamEndingLabels, Counter>,
}

/// Round-trip times, in seconds: 100µs (same rack) .. 1s (a bad mobile link).
fn rtt_histogram() -> Histogram {
    Histogram::new([
        0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
    ])
}

impl KernelMetrics {
    pub fn register(registry: &mut Registry) -> Self {
        let m = KernelMetrics {
            ebpf_attached: Gauge::default(),
            ebpf_lost_events: Gauge::default(),
            client_tcp_rtt_seconds: Family::new_with_constructor(rtt_histogram),
            client_tcp_segments_sent: Family::default(),
            client_tcp_retransmits: Family::default(),
            client_tcp_closes: Family::default(),
            upstream_tcp_rtt_seconds: Family::new_with_constructor(rtt_histogram),
            upstream_tcp_segments_sent: Family::default(),
            upstream_tcp_retransmits: Family::default(),
            upstream_tcp_closes: Family::default(),
        };

        registry.register(
            "gfe_ebpf_attached",
            "Whether the kernel program is attached (1) and the gfe_*_tcp_* metrics are being fed",
            m.ebpf_attached.clone(),
        );
        registry.register(
            "gfe_ebpf_lost_events",
            "Closed connections the kernel could not report because the reader fell behind",
            m.ebpf_lost_events.clone(),
        );
        registry.register(
            "gfe_client_tcp_rtt_seconds",
            "Round-trip time to clients, measured by the kernel, when their connection closed",
            m.client_tcp_rtt_seconds.clone(),
        );
        registry.register(
            "gfe_client_tcp_segments_sent",
            "TCP segments sent to clients on connections that have closed",
            m.client_tcp_segments_sent.clone(),
        );
        registry.register(
            "gfe_client_tcp_retransmits",
            "TCP segments retransmitted to clients on connections that have closed",
            m.client_tcp_retransmits.clone(),
        );
        registry.register(
            "gfe_client_tcp_closes",
            "Closed client connections by how they ended at the TCP level",
            m.client_tcp_closes.clone(),
        );
        registry.register(
            "gfe_upstream_tcp_rtt_seconds",
            "Round-trip time to backends, measured by the kernel, when a connection to them closed",
            m.upstream_tcp_rtt_seconds.clone(),
        );
        registry.register(
            "gfe_upstream_tcp_segments_sent",
            "TCP segments sent to backends on connections that have closed",
            m.upstream_tcp_segments_sent.clone(),
        );
        registry.register(
            "gfe_upstream_tcp_retransmits",
            "TCP segments retransmitted to backends on connections that have closed",
            m.upstream_tcp_retransmits.clone(),
        );
        registry.register(
            "gfe_upstream_tcp_closes",
            "Closed connections to backends by how they ended at the TCP level",
            m.upstream_tcp_closes.clone(),
        );
        m
    }
}

#[cfg(test)]
#[path = "kernel_metrics_test.rs"]
mod tests;
