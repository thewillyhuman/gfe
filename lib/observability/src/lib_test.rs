use super::*;

/// A registry with one counter, counted once, and one histogram, observed
/// once.
fn registry() -> Registry {
    let mut registry = Registry::default();
    let requests = Counter::<u64>::default();
    requests.inc();
    registry.register("requests", "Requests", requests);
    let wait = Histogram::new([0.1, 1.0]);
    wait.observe(0.5);
    registry.register("wait_seconds", "Wait", wait);
    registry
}

#[test]
fn encodes_every_registered_metric_in_the_text_format() {
    let text = encode(&registry());

    assert!(text.contains("# TYPE requests counter\n"), "{text}");
    assert!(text.contains("requests_total 1\n"), "{text}");
    assert!(text.contains("wait_seconds_count 1\n"), "{text}");
    assert!(text.ends_with("# EOF\n"), "{text}");
}

#[test]
fn drops_the_metadata_of_histograms_and_nothing_else() {
    let exposition = "\
# HELP requests Requests.
# TYPE requests counter
requests_total 3
# HELP wait_seconds Wait.
# TYPE wait_seconds histogram
# UNIT wait_seconds seconds
wait_seconds_sum 0.5
wait_seconds_count 2
wait_seconds_bucket{le=\"0.1\"} 1
wait_seconds_bucket{le=\"+Inf\"} 2
# EOF
";

    let untyped = without_histogram_metadata(exposition);

    assert_eq!(
        untyped,
        "\
# HELP requests Requests.
# TYPE requests counter
requests_total 3
wait_seconds_sum 0.5
wait_seconds_count 2
wait_seconds_bucket{le=\"0.1\"} 1
wait_seconds_bucket{le=\"+Inf\"} 2
# EOF
"
    );
}

#[test]
fn keeps_every_sample_when_dropping_histogram_metadata() {
    let exposition = encode(&registry());
    let samples = |text: &str| text.lines().filter(|l| !l.starts_with('#')).count();

    let untyped = without_histogram_metadata(&exposition);

    assert!(exposition.contains(" histogram\n"), "{exposition}");
    assert!(!untyped.contains(" histogram\n"), "{untyped}");
    assert_eq!(samples(&untyped), samples(&exposition));
    assert!(untyped.ends_with("# EOF\n"), "{untyped}");
}
