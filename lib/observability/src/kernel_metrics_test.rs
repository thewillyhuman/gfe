use super::*;

fn exposition() -> String {
    let mut registry = Registry::default();
    KernelMetrics::register(&mut registry);
    let mut text = String::new();
    prometheus_client::encoding::text::encode(&mut text, &registry).expect("encode metrics");
    text
}

#[test]
fn exposes_every_kernel_metric_with_its_type() {
    let text = exposition();

    for (name, kind) in [
        ("gfe_ebpf_attached", "gauge"),
        ("gfe_ebpf_lost_events", "gauge"),
        ("gfe_client_tcp_rtt_seconds", "histogram"),
        ("gfe_client_tcp_segments_sent", "counter"),
        ("gfe_client_tcp_retransmits", "counter"),
        ("gfe_client_tcp_closes", "counter"),
        ("gfe_upstream_tcp_rtt_seconds", "histogram"),
        ("gfe_upstream_tcp_segments_sent", "counter"),
        ("gfe_upstream_tcp_retransmits", "counter"),
        ("gfe_upstream_tcp_closes", "counter"),
    ] {
        assert!(
            text.contains(&format!("# TYPE {name} {kind}\n")),
            "{name} {kind} missing from:\n{text}"
        );
    }
}

#[test]
fn does_not_say_whether_the_kernel_view_is_enabled_since_it_always_is() {
    assert!(!exposition().contains("gfe_ebpf_enabled"));
}

#[test]
fn reports_the_kernel_program_detached_until_told_otherwise() {
    // An alert watches for 0: a node starts out saying it has no kernel view.
    assert!(exposition().contains("\ngfe_ebpf_attached 0\n"));
}
