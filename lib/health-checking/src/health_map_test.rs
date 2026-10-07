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

#[test]
fn a_handle_sees_what_is_set_after_it_was_taken() {
    let h = HealthMap::new(true);
    let backend = h.handle("10.0.0.1", 80);
    assert_eq!(backend.status(), HealthStatus::Unknown);

    h.set("10.0.0.1", 80, HealthStatus::Unhealthy);
    assert_eq!(backend.status(), HealthStatus::Unhealthy);
    assert!(!backend.is_selectable());

    h.set("10.0.0.1", 80, HealthStatus::Healthy);
    assert!(backend.is_selectable());
}

#[test]
fn a_handle_taken_after_a_status_was_set_reads_it() {
    let h = HealthMap::new(true);
    h.set("10.0.0.1", 80, HealthStatus::Draining);

    assert_eq!(h.handle("10.0.0.1", 80).status(), HealthStatus::Draining);
}

#[test]
fn a_handle_on_an_unprobed_backend_trusts_it_as_the_map_does() {
    assert!(HealthMap::new(true).handle("10.0.0.1", 80).is_selectable());
    assert!(!HealthMap::new(false).handle("10.0.0.1", 80).is_selectable());
}

#[test]
fn a_handle_names_one_backend_by_host_and_port() {
    let h = HealthMap::new(true);
    h.set("10.0.0.1", 80, HealthStatus::Unhealthy);

    assert!(!h.handle("10.0.0.1", 80).is_selectable());
    assert!(h.handle("10.0.0.1", 81).is_selectable());
    assert!(h.handle("10.0.0.2", 80).is_selectable());
}

#[test]
fn retain_forgets_the_backends_not_kept() {
    let h = HealthMap::new(true);
    h.set("10.0.0.1", 80, HealthStatus::Unhealthy);
    h.set("10.0.0.2", 80, HealthStatus::Unhealthy);

    h.retain(&[("10.0.0.2".to_string(), 80)]);

    assert_eq!(h.get("10.0.0.1", 80), HealthStatus::Unknown);
    assert_eq!(h.get("10.0.0.2", 80), HealthStatus::Unhealthy);
    assert_eq!(h.len(), 1);
}

#[test]
fn a_handle_on_a_forgotten_backend_keeps_its_last_status() {
    let h = HealthMap::new(true);
    h.set("10.0.0.1", 80, HealthStatus::Unhealthy);
    let backend = h.handle("10.0.0.1", 80);

    h.retain(&[]);

    assert!(!backend.is_selectable());
}
