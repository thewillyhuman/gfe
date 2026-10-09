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

#[test]
fn cpu_is_charged_per_answered_request() {
    let mut outcome = Outcome::measure("x", "keepalive", &mut [1_000; 4], 0, 1.0);

    outcome.charge_cpu(Duration::from_micros(200));

    assert_eq!(outcome.cpu_us_per_request, Some(50.0));
    assert!(outcome.to_string().ends_with("errors=0  cpu=50µs/req"));
}

#[test]
fn cpu_of_a_run_that_answered_nothing_is_zero_not_infinite() {
    let mut outcome = Outcome::measure("x", "keepalive", &mut [], 3, 1.0);

    outcome.charge_cpu(Duration::from_secs(1));

    assert_eq!(outcome.cpu_us_per_request, Some(0.0));
}

#[test]
fn outcomes_are_appended_to_a_file_as_one_json_line_each() {
    let dir = std::env::temp_dir().join(format!("gfe-loadtest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("outcomes.jsonl");
    let mut first = Outcome::measure("a", "keepalive", &mut [1_000, 2_000], 0, 1.0);
    first.charge_cpu(Duration::from_micros(100));
    let second = Outcome::measure("b", "reconnect", &mut [], 2, 1.0);

    first.append_to(&path).unwrap();
    second.append_to(&path).unwrap();

    let lines: Vec<Outcome> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines, vec![first.clone(), second.clone()]);
    assert_eq!(Outcome::read_all(&path).unwrap(), vec![first, second]);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_file_that_is_not_outcomes_is_rejected() {
    let dir = std::env::temp_dir().join(format!("gfe-loadtest-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("outcomes.jsonl");
    std::fs::write(&path, "{\"label\": \"a\"}\n").unwrap();

    assert!(Outcome::read_all(&path).is_err());
    assert!(Outcome::read_all(&dir.join("missing.jsonl")).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}
