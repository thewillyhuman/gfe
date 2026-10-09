use super::*;

/// An outcome of `label` with `cpu` µs per request and `errors`.
fn outcome(label: &str, cpu: f64, errors: u64) -> Outcome {
    let mut outcome = Outcome::measure(label, "keepalive", &mut [1_000; 10], errors, 1.0);
    outcome.cpu_us_per_request = Some(cpu);
    outcome
}

#[test]
fn a_scenario_within_the_tolerance_passes_slower_or_faster() {
    let base = [outcome("a", 100.0, 0), outcome("b", 100.0, 0)];
    let head = [outcome("a", 109.0, 0), outcome("b", 80.0, 0)];

    let comparison = Comparison::of(&base, &head, 10.0);

    assert!(comparison.passed(), "{comparison}");
    assert_eq!(comparison.rows[0].verdict, Verdict::Within(9.0));
    assert_eq!(comparison.rows[1].verdict, Verdict::Within(-20.0));
}

#[test]
fn a_scenario_slower_than_the_tolerance_regresses() {
    let base = [outcome("a", 100.0, 0)];
    let head = [outcome("a", 112.0, 0)];

    let comparison = Comparison::of(&base, &head, 10.0);

    assert!(!comparison.passed());
    assert_eq!(comparison.rows[0].verdict, Verdict::Regressed(12.0));
}

#[test]
fn the_best_round_of_each_side_is_compared() {
    // Noise only adds: the lowest CPU of the rounds is the measurement.
    let base = [outcome("a", 130.0, 0), outcome("a", 100.0, 0)];
    let head = [outcome("a", 105.0, 0), outcome("a", 140.0, 0)];

    let comparison = Comparison::of(&base, &head, 10.0);

    assert_eq!(comparison.rows.len(), 1);
    assert_eq!(comparison.rows[0].base_cpu_us, Some(100.0));
    assert_eq!(comparison.rows[0].head_cpu_us, Some(105.0));
    assert_eq!(comparison.rows[0].verdict, Verdict::Within(5.0));
}

#[test]
fn errors_on_either_side_make_the_scenario_unusable() {
    let base = [outcome("a", 100.0, 0), outcome("b", 100.0, 3)];
    let head = [outcome("a", 100.0, 1), outcome("b", 100.0, 0)];

    let comparison = Comparison::of(&base, &head, 10.0);

    assert!(!comparison.passed());
    assert_eq!(
        comparison.rows[0].verdict,
        Verdict::Unusable("1 error in head".into())
    );
    assert_eq!(
        comparison.rows[1].verdict,
        Verdict::Unusable("3 errors in base".into())
    );
}

#[test]
fn a_scenario_without_a_base_or_without_cpu_is_unusable() {
    let mut no_cpu = outcome("b", 0.0, 0);
    no_cpu.cpu_us_per_request = None;
    let base = [outcome("b", 100.0, 0)];
    let head = [outcome("a", 100.0, 0), no_cpu];

    let comparison = Comparison::of(&base, &head, 10.0);

    assert!(!comparison.passed());
    assert_eq!(
        comparison.rows[0].verdict,
        Verdict::Unusable("not in base".into())
    );
    assert_eq!(
        comparison.rows[1].verdict,
        Verdict::Unusable("no cpu in head".into())
    );
}

#[test]
fn rows_follow_the_order_of_the_head_run() {
    let base = [outcome("b", 1.0, 0), outcome("a", 1.0, 0)];
    let head = [
        outcome("a", 1.0, 0),
        outcome("b", 1.0, 0),
        outcome("a", 1.0, 0),
    ];

    let comparison = Comparison::of(&base, &head, 10.0);

    let labels: Vec<&str> = comparison
        .rows
        .iter()
        .map(|row| row.label.as_str())
        .collect();
    assert_eq!(labels, ["a", "b"]);
}

#[test]
fn the_table_says_what_each_scenario_did_and_the_verdict() {
    let base = [outcome("fixed", 33.0, 0), outcome("proxy", 70.0, 0)];
    let head = [outcome("fixed", 33.5, 0), outcome("proxy", 84.0, 0)];

    let table = Comparison::of(&base, &head, 10.0).to_string();

    assert_eq!(
        table,
        "\
scenario                                 base µs/req   head µs/req    change
fixed                                           33.0          33.5     +1.5%
proxy                                           70.0          84.0    +20.0%  REGRESSED
FAILED: 1 scenario beyond the tolerance of 10% on the node's cpu per request
"
    );
}

#[test]
fn the_table_of_a_passed_comparison_says_so() {
    let base = [outcome("fixed", 33.0, 0)];
    let head = [outcome("fixed", 30.0, 0)];

    let table = Comparison::of(&base, &head, 10.0).to_string();

    assert!(
        table.ends_with(
            "passed: no scenario beyond the tolerance of 10% on the node's cpu per request\n"
        ),
        "{table}"
    );
    assert!(table.contains("-9.1%"), "{table}");
}

#[test]
fn an_unusable_scenario_is_printed_with_its_reason() {
    let base = [outcome("fixed", 33.0, 2)];
    let head = [outcome("fixed", 33.0, 0)];

    let table = Comparison::of(&base, &head, 10.0).to_string();

    assert!(table.contains("UNUSABLE: 2 errors in base"), "{table}");
    assert!(table.contains("FAILED: 1 scenario"), "{table}");
}
