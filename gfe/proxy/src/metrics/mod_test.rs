use super::*;
use netkit_observability::without_histogram_metadata;

#[test]
fn encodes_registered_metrics() {
    let m = GfeMetrics::new();
    m.proxy.no_route.inc();
    let out = m.encode();
    assert!(out.contains("gfe_no_route"));
    assert!(out.contains("gfe_backend_health_status"));
}

#[test]
fn reports_build_and_process_start() {
    let out = GfeMetrics::new().encode();
    let version = env!("CARGO_PKG_VERSION");
    assert!(
        out.contains(&format!("gfe_build_info{{version=\"{version}\"}} 1")),
        "{out}"
    );
    assert!(out.contains("process_start_time_seconds "), "{out}");
}

#[test]
fn keeps_every_sample_of_the_node_when_dropping_histogram_metadata() {
    let exposition = GfeMetrics::new().encode();
    let samples = |text: &str| text.lines().filter(|l| !l.starts_with('#')).count();

    let untyped = without_histogram_metadata(&exposition);

    assert!(exposition.contains(" histogram\n"), "{exposition}");
    assert!(!untyped.contains(" histogram\n"), "{untyped}");
    assert_eq!(samples(&untyped), samples(&exposition));
    assert!(untyped.ends_with("# EOF\n"), "{untyped}");
}
