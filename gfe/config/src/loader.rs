//! Read and deserialize the bootstrap (TOML) and dynamic (JSON) configs.

use crate::validator::validate_node_config;
use crate::{ConfigError, DynamicConfig, NodeConfig};
use std::path::{Path, PathBuf};

/// Load the bootstrap node config from a TOML file, and check that its
/// values make sense: a node does not start on a config it cannot honour.
pub fn load_node_config(path: &Path) -> Result<NodeConfig, ConfigError> {
    let text = read(path)?;
    let config: NodeConfig = toml::from_str(&text).map_err(|e| ConfigError::Parse {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    validate_node_config(&config).map_err(|reason| ConfigError::InvalidNodeConfig {
        path: path.to_path_buf(),
        reason,
    })?;
    Ok(config)
}

/// Load the dynamic config (listeners/routes/pools/certs) from a JSON file.
/// It is not validated: see [`crate::validate`].
pub fn load_dynamic_config(path: &Path) -> Result<DynamicConfig, ConfigError> {
    let text = read(path)?;
    serde_json::from_str(&text).map_err(|e| ConfigError::Parse {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })
}

fn read(path: &Path) -> Result<String, ConfigError> {
    std::fs::read_to_string(path).map_err(|error| ConfigError::Read {
        path: PathBuf::from(path),
        error,
    })
}

#[cfg(test)]
#[path = "loader_test.rs"]
mod tests;
