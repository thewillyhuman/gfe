use super::*;

#[test]
fn exposes_every_control_metric_with_its_type() {
    let mut registry = Registry::default();
    ControlMetrics::register(&mut registry);
    let text = netkit_observability::encode(&registry);

    for (name, kind) in [
        ("gfe_backend_health_status", "gauge"),
        ("gfe_backend_draining", "gauge"),
        ("gfe_health_check_duration_seconds", "histogram"),
        ("gfe_config_last_reload_timestamp", "gauge"),
        ("gfe_config_reload_errors", "counter"),
        ("gfe_config_reload_failed", "gauge"),
        ("gfe_config_from_cache", "gauge"),
        ("gfe_upgrade_failures", "counter"),
        ("gfe_cert_expiry_timestamp", "gauge"),
        ("gfe_active_routes", "gauge"),
        ("gfe_active_pools", "gauge"),
    ] {
        assert!(
            text.contains(&format!("# TYPE {name} {kind}\n")),
            "{name} {kind} missing from:\n{text}"
        );
    }
}
