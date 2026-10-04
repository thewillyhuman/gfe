//! The kernel's view of the node's TCP connections (`gfe-ebpf`), turned into
//! what the rest of the node already speaks: an answer for the proxy's
//! accept-queue question, metrics, and one `gfe::tcp` log event per closed
//! connection.
//!
//! It is optional. When it is not enabled, or cannot be attached, the node
//! runs exactly as it does without it.

use gfe_core::config::NodeConfig;
use gfe_core::server::AcceptQueue;
use gfe_ebpf::{ClosedConnection, ClosedConnections, Ending, Origin, TcpProbe};
use gfe_observability::{
    BackendLabel, ClientEndingLabels, GfeMetrics, KernelMetrics, ListenerLabel,
    UpstreamEndingLabels,
};
use gfe_proxy::ListenerSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// The attached kernel program, as the proxy and the ops server use it.
pub struct KernelView {
    probe: TcpProbe,
}

impl KernelView {
    /// Closed connections the kernel could not report.
    pub fn lost_events(&self) -> u64 {
        self.probe.lost_events()
    }
}

impl AcceptQueue for KernelView {
    fn waited(&self, local: SocketAddr, peer: SocketAddr) -> Option<Duration> {
        self.probe.accept_queue_wait(local, peer)
    }
}

/// Attach the kernel program if the config asks for it. `None` if it is not
/// enabled or cannot be attached, which is logged and never fatal:
/// observability must not be what keeps a node from serving. That it was
/// asked for is exported either way, so that a failure to attach can be
/// alerted on.
pub fn attach(
    node: &NodeConfig,
    metrics: &GfeMetrics,
) -> Option<(Arc<KernelView>, ClosedConnections)> {
    if !node.ebpf.enabled {
        return None;
    }
    metrics.kernel.ebpf_enabled.set(1);
    // The program keeps a record per open connection, client and upstream.
    let connections = node
        .limits
        .max_connections
        .saturating_add(node.limits.max_upstream_connections);
    match TcpProbe::attach(u32::try_from(connections).unwrap_or(u32::MAX)) {
        Ok((probe, closed)) => {
            metrics.kernel.ebpf_attached.set(1);
            tracing::info!(connections, "kernel tcp statistics enabled (eBPF attached)");
            Some((Arc::new(KernelView { probe }), closed))
        }
        Err(reason) => {
            tracing::warn!(%reason, "kernel tcp statistics unavailable; continuing without them");
            None
        }
    }
}

/// Report every connection the kernel says has closed, until the node exits.
pub async fn report(
    mut closed: ClosedConnections,
    listeners: Arc<ListenerSet>,
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
/// Connections accepted on anything else (the ops server being scraped) are
/// not client traffic and are left out.
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
mod tests {
    use super::*;

    fn closed(origin: Origin, ending: Ending) -> ClosedConnection {
        ClosedConnection {
            local: "10.0.0.1:443".parse().unwrap(),
            peer: "192.0.2.7:50000".parse().unwrap(),
            origin,
            ending,
            lifetime: Duration::from_secs(2),
            rtt: Duration::from_millis(20),
            min_rtt: Duration::from_millis(18),
            retransmits: 3,
            segments_sent: 100,
            bytes_acked: 4096,
            bytes_received: 512,
        }
    }

    #[test]
    fn counts_a_client_connection_under_its_listener() {
        let metrics = GfeMetrics::new();

        record(
            &metrics.kernel,
            &closed(Origin::Accepted, Ending::PeerClosed),
            Some("https".into()),
        );

        let exposed = metrics.encode();
        for expected in [
            r#"gfe_client_tcp_retransmits_total{listener="https"} 3"#,
            r#"gfe_client_tcp_segments_sent_total{listener="https"} 100"#,
            r#"gfe_client_tcp_closes_total{listener="https",ending="peer_closed"} 1"#,
            r#"gfe_client_tcp_rtt_seconds_count{listener="https"} 1"#,
        ] {
            assert!(
                exposed.contains(expected),
                "missing {expected} in:\n{exposed}"
            );
        }
    }

    #[test]
    fn counts_an_upstream_connection_under_its_backend() {
        let metrics = GfeMetrics::new();

        record(
            &metrics.kernel,
            &closed(Origin::Connected, Ending::Aborted),
            None,
        );

        let exposed = metrics.encode();
        for expected in [
            r#"gfe_upstream_tcp_retransmits_total{backend="192.0.2.7:50000"} 3"#,
            r#"gfe_upstream_tcp_closes_total{backend="192.0.2.7:50000",ending="aborted"} 1"#,
            r#"gfe_upstream_tcp_rtt_seconds_count{backend="192.0.2.7:50000"} 1"#,
        ] {
            assert!(
                exposed.contains(expected),
                "missing {expected} in:\n{exposed}"
            );
        }
    }

    /// A node config whose `[ebpf]` section says `enabled = {enabled}`.
    fn node_config(enabled: bool) -> NodeConfig {
        let path =
            std::env::temp_dir().join(format!("gfe-kernel-{}-{enabled}.toml", std::process::id()));
        std::fs::write(
            &path,
            format!(
                "[node]\nid = \"t\"\nloopback_vip = \"127.0.0.1\"\n\
                 metrics_addr = \"127.0.0.1:9101\"\n\n\
                 [control_plane]\nconfig_file = \"gfe-dynamic.json\"\n\
                 local_cache = \"config-cache.json\"\n\n\
                 [ebpf]\nenabled = {enabled}\n\n[health_check_defaults]\n"
            ),
        )
        .unwrap();
        gfe_core::config::load_node_config(&path).unwrap()
    }

    /// Asked for and not attached (on this host: no Linux, or not the
    /// capabilities) is what an alert must be able to tell from "not asked
    /// for". Where it does attach, it needs the runtime to read the kernel's
    /// reports.
    #[tokio::test]
    async fn exports_that_the_kernel_view_is_asked_for_whether_or_not_it_attaches() {
        let metrics = GfeMetrics::new();

        let attached = attach(&node_config(true), &metrics).is_some();

        let exposed = metrics.encode();
        assert!(exposed.contains("gfe_ebpf_enabled 1\n"), "{exposed}");
        let expected = format!("gfe_ebpf_attached {}\n", u8::from(attached));
        assert!(exposed.contains(&expected), "{exposed}");
    }

    #[test]
    fn exports_that_the_kernel_view_is_not_asked_for() {
        let metrics = GfeMetrics::new();

        attach(&node_config(false), &metrics);

        let exposed = metrics.encode();
        assert!(exposed.contains("gfe_ebpf_enabled 0\n"), "{exposed}");
        assert!(exposed.contains("gfe_ebpf_attached 0\n"), "{exposed}");
    }

    /// A scrape of the ops server is a connection the node accepts, but it
    /// is not client traffic.
    #[test]
    fn leaves_out_connections_accepted_outside_the_proxy_listeners() {
        let metrics = GfeMetrics::new();

        record(
            &metrics.kernel,
            &closed(Origin::Accepted, Ending::PeerClosed),
            None,
        );

        let exposed = metrics.encode();
        assert!(
            !exposed.contains("gfe_client_tcp_closes_total{"),
            "{exposed}"
        );
        assert!(
            !exposed.contains("gfe_upstream_tcp_closes_total{"),
            "{exposed}"
        );
    }
}
