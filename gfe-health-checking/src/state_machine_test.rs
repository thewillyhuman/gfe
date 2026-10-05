use super::*;

use ProbeResult::{Drain, Fail, Pass};

#[test]
fn transitions_after_thresholds() {
    let mut bh = BackendHealth::default();
    assert_eq!(bh.status(), HealthStatus::Unknown);
    assert_eq!(bh.record(Pass, 2, 3), None);
    assert_eq!(bh.record(Pass, 2, 3), Some(HealthStatus::Healthy));
    assert_eq!(bh.record(Fail, 2, 3), None);
    assert_eq!(bh.record(Fail, 2, 3), None);
    assert_eq!(bh.record(Fail, 2, 3), Some(HealthStatus::Unhealthy));
}

#[test]
fn unknown_to_unhealthy() {
    let mut bh = BackendHealth::default();
    assert_eq!(bh.record(Fail, 2, 2), None);
    assert_eq!(bh.record(Fail, 2, 2), Some(HealthStatus::Unhealthy));
}

#[test]
fn success_resets_failures() {
    let mut bh = BackendHealth::default();
    bh.record(Fail, 2, 3);
    bh.record(Fail, 2, 3);
    bh.record(Pass, 2, 3); // resets failure run
    assert_eq!(bh.record(Fail, 2, 3), None);
}

#[test]
fn drain_takes_effect_immediately() {
    let mut bh = BackendHealth::default();
    bh.record(Pass, 1, 1); // → Healthy
    assert_eq!(bh.record(Drain, 2, 3), Some(HealthStatus::Draining));
    // Idempotent while draining.
    assert_eq!(bh.record(Drain, 2, 3), None);
    // Recovery back to Healthy after threshold passes.
    assert_eq!(bh.record(Pass, 1, 3), Some(HealthStatus::Healthy));
}
