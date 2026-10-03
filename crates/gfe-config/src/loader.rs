//! Read and deserialize the bootstrap (TOML) and dynamic (JSON) configs.

use gfe_types::{DynamicConfig, GfeError, NodeConfig};
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
    Ok(config)
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

    #[test]
    fn reports_missing_file() {
        let err = load_dynamic_config(Path::new("/nonexistent/gfe.json"));
        assert!(err.is_err());
    }
}
