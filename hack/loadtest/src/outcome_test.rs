use super::*;

#[test]
fn percentiles_are_read_from_the_sorted_latencies() {
    // 1 to 100 µs, shuffled: the percentile is the nearest rank, rounded.
    let mut latencies: Vec<u64> = (1..=100).rev().map(|n| n * 1000).collect();

    let outcome = Outcome::measure("x", "keepalive", &mut latencies, 0, 2.0);

    assert_eq!(outcome.requests, 100);
    assert_eq!(outcome.requests_per_second, 50.0);
    assert_eq!(outcome.p50_us, 51.0);
    assert_eq!(outcome.p90_us, 90.0);
    assert_eq!(outcome.p99_us, 99.0);
    assert_eq!(outcome.max_us, 100.0);
}

#[test]
fn a_run_that_answered_nothing_reports_zeros_not_a_panic() {
    let outcome = Outcome::measure("x", "reconnect", &mut [], 7, 1.0);

    assert_eq!(outcome.requests, 0);
    assert_eq!(outcome.p99_us, 0.0);
    assert_eq!(outcome.errors, 7);
}

#[test]
fn the_row_aligns_its_columns() {
    let outcome = Outcome::measure("http · fixed", "keepalive", &mut [1_500, 2_500], 0, 1.0);

    assert_eq!(
        outcome.to_string(),
        "http · fixed                           keepalive  reqs=2                  2 req/s  p50=     2.5µs p90=     2.5µs p99=      2.5µs max=      2.5µs errors=0"
    );
}
