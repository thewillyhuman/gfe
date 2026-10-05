use super::*;

/// A path in the temporary directory that no other test uses.
fn temp_path(test: &str, extension: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "gfe-config-{}-{test}.{extension}",
        std::process::id()
    ))
}

#[test]
fn loads_dynamic_json() {
    let json =
        r#"{"listeners":[{"id":"https","address":"0.0.0.0","port":443,"protocol":"https"}]}"#;
    let path = temp_path("dynamic", "json");
    std::fs::write(&path, json).unwrap();

    let cfg = load_dynamic_config(&path).unwrap();

    assert_eq!(cfg.listeners.len(), 1);
}

#[test]
fn reports_missing_file() {
    let err = load_dynamic_config(Path::new("/nonexistent/gfe.json")).unwrap_err();

    assert!(matches!(err, ConfigError::Read { .. }), "{err}");
    assert!(err.to_string().contains("/nonexistent/gfe.json"), "{err}");
}

#[test]
fn reports_which_dynamic_file_does_not_parse() {
    let path = temp_path("dynamic-garbage", "json");
    std::fs::write(&path, "{").unwrap();

    let err = load_dynamic_config(&path).unwrap_err();

    assert!(matches!(err, ConfigError::Parse { .. }), "{err}");
    assert!(err.to_string().contains(&*path.to_string_lossy()), "{err}");
}

/// Write a minimal bootstrap config with `extra` (TOML tables, headers
/// included) appended, and load it.
fn load_node(test: &str, extra: &str) -> Result<NodeConfig, ConfigError> {
    let toml = format!(
        "[node]\nid = \"t\"\n\n\
         [control_plane]\nconfig_file = \"/etc/gfe/gfe-dynamic.json\"\n\n\
         [health_check_defaults]\n\n{extra}\n"
    );
    let path = temp_path(test, "toml");
    std::fs::write(&path, toml).unwrap();
    load_node_config(&path)
}

#[test]
fn loads_a_minimal_node_config() {
    assert!(load_node("minimal", "").is_ok());
}

#[test]
fn reports_which_node_file_does_not_parse() {
    let err = load_node("unknown-key", "[limits]\nmax_conections = 1").unwrap_err();

    assert!(matches!(err, ConfigError::Parse { .. }), "{err}");
    assert!(err.to_string().contains("max_conections"), "{err}");
}

#[test]
fn reports_which_node_file_is_invalid() {
    let err = load_node("invalid", "[limits]\nmax_header_bytes = 1024").unwrap_err();

    assert!(
        matches!(err, ConfigError::InvalidNodeConfig { .. }),
        "{err}"
    );
    assert!(err.to_string().contains("invalid.toml"), "{err}");
    assert!(err.to_string().contains("max_header_bytes"), "{err}");
}
