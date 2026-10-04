//! Read and deserialize the bootstrap (TOML) and dynamic (JSON) configs.

use crate::validator::validate_health_check;
use gfe_core::config::{DynamicConfig, NodeConfig, UpstreamConfig};
use gfe_core::GfeError;
use std::path::Path;

/// The smallest `limits.max_header_bytes` the HTTP server can be given: it
/// needs at least this much buffer to read a request head.
pub const MIN_HEADER_BYTES: usize = 8192;

/// Load the bootstrap node config from a TOML file.
pub fn load_node_config(path: &Path) -> Result<NodeConfig, GfeError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| GfeError::Config(format!("reading {}: {e}", path.display())))?;
    let config: NodeConfig = toml::from_str(&text)
        .map_err(|e| GfeError::Config(format!("parsing {}: {e}", path.display())))?;
    if config.limits.max_header_bytes < MIN_HEADER_BYTES {
        return Err(GfeError::Config(format!(
            "{}: limits.max_header_bytes must be at least {MIN_HEADER_BYTES}, got {}",
            path.display(),
            config.limits.max_header_bytes
        )));
    }
    validate_health_check(&config.health_check_defaults)
        .map_err(|e| GfeError::Config(format!("{}: health_check_defaults.{e}", path.display())))?;
    validate_limits_and_timeouts(&config)
        .and_then(|()| validate_upstream_client_identity(&config.upstream))
        .map_err(|e| GfeError::Config(format!("{}: {e}", path.display())))?;
    Ok(config)
}

/// Reject a limit or timeout of zero. None of them means "unlimited": a
/// zero limit refuses everything and a zero timeout expires at once.
fn validate_limits_and_timeouts(config: &NodeConfig) -> Result<(), String> {
    let l = &config.limits;
    let limits = [
        ("max_connections", l.max_connections),
        ("max_connections_listener", l.max_connections_listener),
        (
            "max_h2_concurrent_streams",
            l.max_h2_concurrent_streams as usize,
        ),
        ("max_upstream_connections", l.max_upstream_connections),
    ];
    if let Some((name, _)) = limits.iter().find(|(_, value)| *value == 0) {
        return Err(format!(
            "limits.{name} must be greater than 0 (0 is not \"unlimited\": \
             it refuses everything); remove it to use the default"
        ));
    }

    let t = &config.timeouts;
    let timeouts = [
        ("tls_handshake", t.tls_handshake),
        ("request_header", t.request_header),
        ("upstream_connect", t.upstream_connect),
        ("upstream_first_byte", t.upstream_first_byte),
        ("request_total", t.request_total),
        ("client_idle", t.client_idle),
        ("drain_deadline", t.drain_deadline),
    ];
    if let Some((name, _)) = timeouts.iter().find(|(_, value)| value.is_zero()) {
        return Err(format!(
            "timeouts.{name} must be greater than 0s (a zero timeout expires \
             at once); remove it to use the default"
        ));
    }
    Ok(())
}

/// Reject half a client identity: without both its certificate and its key
/// the node would silently not present one, and backends requiring mutual
/// TLS would refuse every connection.
fn validate_upstream_client_identity(upstream: &UpstreamConfig) -> Result<(), String> {
    match (&upstream.client_cert_file, &upstream.client_key_file) {
        (Some(_), None) => Err(
            "upstream.client_cert_file is set but upstream.client_key_file is not: \
             set both for mutual TLS, or neither"
                .into(),
        ),
        (None, Some(_)) => Err(
            "upstream.client_key_file is set but upstream.client_cert_file is not: \
             set both for mutual TLS, or neither"
                .into(),
        ),
        _ => Ok(()),
    }
}

/// Load the dynamic config (listeners/routes/pools/certs) from a JSON file.
pub fn load_dynamic_config(path: &Path) -> Result<DynamicConfig, GfeError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| GfeError::Config(format!("reading {}: {e}", path.display())))?;
    serde_json::from_str(&text)
        .map_err(|e| GfeError::Config(format!("parsing {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn loads_dynamic_json() {
        let json =
            r#"{"listeners":[{"id":"https","address":"0.0.0.0","port":443,"protocol":"https"}]}"#;
        let dir = std::env::temp_dir();
        let path = dir.join(format!("gfe-cfg-{}.json", std::process::id()));
        std::fs::File::create(&path)
            .unwrap()
            .write_all(json.as_bytes())
            .unwrap();
        let cfg = load_dynamic_config(&path).unwrap();
        assert_eq!(cfg.listeners.len(), 1);
    }

    #[test]
    fn rejects_max_header_bytes_below_minimum() {
        let toml = "[node]\nid = \"t\"\nloopback_vip = \"127.0.0.1\"\n\n\
                    [control_plane]\nconfig_file = \"/etc/gfe/gfe-dynamic.json\"\n\n\
                    [limits]\nmax_header_bytes = 1024\n\n\
                    [health_check_defaults]\n";
        let path = std::env::temp_dir().join(format!("gfe-node-{}.toml", std::process::id()));
        std::fs::write(&path, toml).unwrap();

        let err = load_node_config(&path).unwrap_err();

        assert!(err.to_string().contains("max_header_bytes"), "{err}");
    }

    /// Write a bootstrap config with `extra` appended to the
    /// `[health_check_defaults]` section, and load it.
    fn load_with_check_defaults(test: &str, extra: &str) -> Result<NodeConfig, GfeError> {
        let toml = format!(
            "[node]\nid = \"t\"\nloopback_vip = \"127.0.0.1\"\n\n\
             [control_plane]\nconfig_file = \"/etc/gfe/gfe-dynamic.json\"\n\n\
             [health_check_defaults]\n{extra}\n"
        );
        let path =
            std::env::temp_dir().join(format!("gfe-node-{}-{test}.toml", std::process::id()));
        std::fs::write(&path, toml).unwrap();
        load_node_config(&path)
    }

    #[test]
    fn accepts_default_health_check_defaults() {
        assert!(load_with_check_defaults("check-ok", "").is_ok());
    }

    #[test]
    fn rejects_health_check_defaults_with_a_zero_timeout() {
        let err = load_with_check_defaults("check-timeout", "timeout = \"0s\"").unwrap_err();

        assert!(
            err.to_string().contains("health_check_defaults.timeout"),
            "{err}"
        );
    }

    #[test]
    fn rejects_health_check_defaults_with_an_interval_below_100ms() {
        let err = load_with_check_defaults("check-interval", "interval = \"10ms\"").unwrap_err();

        assert!(
            err.to_string().contains("health_check_defaults.interval"),
            "{err}"
        );
    }

    #[test]
    fn rejects_health_check_defaults_with_a_relative_path() {
        let err = load_with_check_defaults("check-path", "path = \"healthz\"").unwrap_err();

        assert!(
            err.to_string().contains("health_check_defaults.path"),
            "{err}"
        );
    }

    #[test]
    fn rejects_health_check_defaults_with_an_impossible_status() {
        let err = load_with_check_defaults("check-status", "expected_status = 1000").unwrap_err();

        assert!(
            err.to_string()
                .contains("health_check_defaults.expected_status"),
            "{err}"
        );
    }

    /// Write a minimal bootstrap config with `section` (a TOML table, header
    /// included) added, and load it.
    fn load_with_section(test: &str, section: &str) -> Result<NodeConfig, GfeError> {
        load_with_check_defaults(test, &format!("\n{section}"))
    }

    #[test]
    fn rejects_a_zero_limit() {
        for limit in [
            "max_connections",
            "max_connections_listener",
            "max_h2_concurrent_streams",
            "max_upstream_connections",
        ] {
            let section = format!("[limits]\n{limit} = 0");

            let err = load_with_section(&format!("limit-{limit}"), &section).unwrap_err();

            assert!(
                err.to_string().contains(&format!("limits.{limit}")),
                "{err}"
            );
        }
    }

    #[test]
    fn rejects_a_zero_timeout() {
        for timeout in [
            "tls_handshake",
            "request_header",
            "upstream_connect",
            "upstream_first_byte",
            "request_total",
            "client_idle",
            "drain_deadline",
        ] {
            let section = format!("[timeouts]\n{timeout} = \"0s\"");

            let err = load_with_section(&format!("timeout-{timeout}"), &section).unwrap_err();

            assert!(
                err.to_string().contains(&format!("timeouts.{timeout}")),
                "{err}"
            );
        }
    }

    #[test]
    fn rejects_an_upstream_client_certificate_without_its_key() {
        let section = "[upstream]\nclient_cert_file = \"/etc/gfe/client.crt\"";

        let err = load_with_section("client-cert", section).unwrap_err();

        assert!(
            err.to_string().contains("upstream.client_key_file"),
            "{err}"
        );
    }

    #[test]
    fn rejects_an_upstream_client_key_without_its_certificate() {
        let section = "[upstream]\nclient_key_file = \"/etc/gfe/client.key\"";

        let err = load_with_section("client-key", section).unwrap_err();

        assert!(
            err.to_string().contains("upstream.client_cert_file"),
            "{err}"
        );
    }

    #[test]
    fn accepts_an_upstream_client_certificate_with_its_key() {
        let section = "[upstream]\nclient_cert_file = \"/etc/gfe/client.crt\"\n\
                       client_key_file = \"/etc/gfe/client.key\"";

        assert!(load_with_section("client-pair", section).is_ok());
    }

    /// A file of the repository's `config/` directory, which the package
    /// ships as the examples.
    fn shipped_example(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config")
            .join(name)
    }

    #[test]
    fn example_node_config_loads() {
        assert!(load_node_config(&shipped_example("gfe.example.toml")).is_ok());
    }

    /// The paths the package and its systemd unit provide: the cache must
    /// survive a stop, which `/tmp` does not under `PrivateTmp=yes`.
    #[test]
    fn example_node_config_uses_the_packaged_paths() {
        let node = load_node_config(&shipped_example("gfe.example.toml")).unwrap();

        assert_eq!(
            node.control_plane.config_file,
            Path::new("/etc/gfe/gfe-dynamic.json")
        );
        assert_eq!(
            node.control_plane.local_cache.as_deref(),
            Some(Path::new("/var/lib/gfe/config-cache.json"))
        );
    }

    /// Certificates are not loaded: the files it names exist only on a node.
    #[test]
    fn example_dynamic_config_loads_and_validates() {
        let cfg = load_dynamic_config(&shipped_example("gfe-dynamic.example.json")).unwrap();

        assert!(crate::validate(&cfg).is_ok());
    }

    #[test]
    fn reports_missing_file() {
        let err = load_dynamic_config(Path::new("/nonexistent/gfe.json"));
        assert!(err.is_err());
    }
}
