use super::*;

#[test]
fn optimistic_unknown() {
    let h = HealthMap::new(true);
    assert!(h.is_selectable("10.0.0.1", 80));
    h.set("10.0.0.1", 80, HealthStatus::Unhealthy);
    assert!(!h.is_selectable("10.0.0.1", 80));
}

#[test]
fn pessimistic_unknown() {
    let h = HealthMap::new(false);
    assert!(!h.is_selectable("10.0.0.1", 80));
    h.set("10.0.0.1", 80, HealthStatus::Healthy);
    assert!(h.is_selectable("10.0.0.1", 80));
}

#[test]
fn only_a_healthy_backend_is_selectable() {
    assert!(HealthStatus::Healthy.is_selectable());
    assert!(!HealthStatus::Draining.is_selectable());
    assert!(!HealthStatus::Unhealthy.is_selectable());
    assert!(!HealthStatus::Unknown.is_selectable());
}
