use super::*;
use crate::proxy::test_support::node_config;

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

/// A scrape of the ops endpoint is a connection the node accepts, but it
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

#[test]
fn names_every_ending() {
    let labels = [
        Ending::PeerClosed,
        Ending::NodeClosed,
        Ending::Aborted,
        Ending::Other,
    ]
    .map(ending_label);

    assert_eq!(labels, ["peer_closed", "node_closed", "aborted", "other"]);
}

/// Attaching needs Linux and the capabilities to load eBPF. Where it does
/// attach, it needs the runtime to read the kernel's reports.
#[tokio::test]
async fn exports_whether_the_kernel_view_is_attached() {
    let metrics = GfeMetrics::new();

    let attached = attach(&node_config(), &metrics).is_some();

    let exposed = metrics.encode();
    let expected = format!("gfe_ebpf_attached {}\n", u8::from(attached));
    assert!(exposed.contains(&expected), "{exposed}");
}

#[cfg(not(target_os = "linux"))]
#[test]
fn does_not_attach_outside_linux() {
    let metrics = GfeMetrics::new();

    assert!(attach(&node_config(), &metrics).is_none());

    assert!(metrics.encode().contains("gfe_ebpf_attached 0\n"));
}
