//! Read and deserialize the bootstrap (TOML) and dynamic (JSON) configs.

use gfe_types::{DynamicConfig, GfeError, NodeConfig};
use std::path::Path;

/// Load the bootstrap node config from a TOML file.
pub fn load_node_config(path: &Path) -> Result<NodeConfig, GfeError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| GfeError::Config(format!("reading {}: {e}", path.display())))?;
    toml::from_str(&text).map_err(|e| GfeError::Config(format!("parsing {}: {e}", path.display())))
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
    fn reports_missing_file() {
        let err = load_dynamic_config(Path::new("/nonexistent/gfe.json"));
        assert!(err.is_err());
    }
}
