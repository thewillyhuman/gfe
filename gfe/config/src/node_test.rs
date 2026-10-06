use super::*;

/// The smallest bootstrap config there is, with `extra` (whole TOML tables,
/// headers included) appended.
fn node_config(extra: &str) -> NodeConfig {
    let toml_str = format!(
        r#"
[node]
id = "gfe-node-01"

[control_plane]
config_file = "/etc/gfe/gfe-dynamic.json"

[health_check_defaults]

{extra}
"#
    );
    toml::from_str(&toml_str).unwrap()
}

#[test]
fn node_config_minimal_toml() {
    let cfg = node_config("");
    assert_eq!(cfg.node.id, "gfe-node-01");
    assert_eq!(cfg.node.metrics_addr.port(), 9101);
    assert_eq!(
        cfg.control_plane.reload_debounce,
        Duration::from_millis(250)
    );
    assert_eq!(cfg.limits.max_connections, 100_000);
    assert_eq!(cfg.timeouts.upstream_connect, Duration::from_secs(3));
    assert_eq!(cfg.health_check_defaults.interval, Duration::from_secs(5));
}

#[test]
fn loopback_vip_is_optional() {
    assert_eq!(node_config("").node.loopback_vip, None);
}

#[test]
fn a_file_that_sets_loopback_vip_still_loads() {
    let toml_str = r#"
[node]
id = "gfe-node-01"
loopback_vip = "188.184.100.10"

[control_plane]
config_file = "/etc/gfe/gfe-dynamic.json"

[health_check_defaults]
"#;
    let cfg: NodeConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(
        cfg.node.loopback_vip,
        Some("188.184.100.10".parse().unwrap())
    );
}

#[test]
fn a_file_with_an_ebpf_section_still_loads() {
    let cfg = node_config("[ebpf]\nenabled = true");
    assert_eq!(cfg.ebpf, Some(EbpfConfig { enabled: true }));
}

#[test]
fn ebpf_section_rejects_unknown_keys() {
    let toml_str = r#"
[node]
id = "gfe-node-01"

[control_plane]
config_file = "/etc/gfe/gfe-dynamic.json"

[ebpf]
enable = true

[health_check_defaults]
"#;
    assert!(toml::from_str::<NodeConfig>(toml_str).is_err());
}

#[test]
fn rejects_an_unknown_section() {
    let toml_str = r#"
[node]
id = "gfe-node-01"

[control_plane]
config_file = "/etc/gfe/gfe-dynamic.json"

[acme]
enabled = true

[health_check_defaults]
"#;
    let err = toml::from_str::<NodeConfig>(toml_str).unwrap_err();
    assert!(err.to_string().contains("acme"), "{err}");
}

#[test]
fn upstream_idle_timeout_defaults_to_a_minute() {
    assert_eq!(
        UpstreamConfig::default().idle_timeout,
        Duration::from_secs(60)
    );
    let cfg: UpstreamConfig = toml::from_str("").unwrap();
    assert_eq!(cfg.idle_timeout, Duration::from_secs(60));
}

#[test]
fn upstream_idle_timeout_is_a_duration() {
    let cfg: UpstreamConfig = toml::from_str(r#"idle_timeout = "15s""#).unwrap();
    assert_eq!(cfg.idle_timeout, Duration::from_secs(15));
}

#[test]
fn upstream_idle_per_host_is_read() {
    let cfg: UpstreamConfig = toml::from_str("idle_per_host = 8").unwrap();
    assert_eq!(cfg.idle_per_host, Some(8));
}

#[test]
fn upstream_idle_per_host_is_unset_by_default() {
    assert_eq!(UpstreamConfig::default().idle_per_host, None);
}

#[test]
fn upstream_idle_connections_is_not_a_key() {
    let parsed = toml::from_str::<UpstreamConfig>("idle_connections = 64");
    assert!(parsed.is_err(), "{parsed:?}");
}

#[test]
fn a_file_without_deprecated_keys_has_no_deprecations() {
    assert!(node_config("").deprecations().is_empty());
}

#[test]
fn loopback_vip_is_reported_as_deprecated() {
    let mut cfg = node_config("");
    cfg.node.loopback_vip = Some("192.0.2.1".parse().unwrap());

    let deprecations = cfg.deprecations();

    assert_eq!(deprecations.len(), 1, "{deprecations:?}");
    assert!(deprecations[0].contains("loopback_vip"), "{deprecations:?}");
}

#[test]
fn an_ebpf_section_is_reported_as_deprecated_even_when_disabled() {
    let deprecations = node_config("[ebpf]\nenabled = false").deprecations();

    assert_eq!(deprecations.len(), 1, "{deprecations:?}");
    assert!(deprecations[0].contains("[ebpf]"), "{deprecations:?}");
}

#[test]
fn idle_per_host_is_not_deprecated() {
    assert!(
        node_config("[upstream]\nidle_per_host = 32")
            .deprecations()
            .is_empty()
    );
}
