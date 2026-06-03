//! Last-known-good cache of the dynamic config, so a restarted node can serve
//! traffic immediately even if the source of the config file is unavailable.

use gfe_types::{DynamicConfig, GfeError};
use std::path::Path;

/// Write the dynamic config to the cache path atomically (temp file + rename).
pub fn write(path: &Path, cfg: &DynamicConfig) -> Result<(), GfeError> {
    let json = serde_json::to_string_pretty(cfg)
        .map_err(|e| GfeError::Config(format!("serializing cache: {e}")))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, json.as_bytes())
        .map_err(|e| GfeError::Config(format!("writing cache {}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| GfeError::Config(format!("renaming cache {}: {e}", path.display())))?;
    Ok(())
}

/// Read the dynamic config from the cache path.
pub fn read(path: &Path) -> Result<DynamicConfig, GfeError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| GfeError::Config(format!("reading cache {}: {e}", path.display())))?;
    serde_json::from_str(&text)
        .map_err(|e| GfeError::Config(format!("parsing cache {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gfe_types::{ListenProtocol, Listener, ListenerId};

    #[test]
    fn round_trip() {
        let cfg = DynamicConfig {
            listeners: vec![Listener {
                id: ListenerId("http".into()),
                address: "127.0.0.1".parse().unwrap(),
                port: 80,
                protocol: ListenProtocol::Http,
            }],
            ..Default::default()
        };
        let path = std::env::temp_dir().join(format!("gfe-cache-{}.json", std::process::id()));
        write(&path, &cfg).unwrap();
        let back = read(&path).unwrap();
        assert_eq!(back.listeners.len(), 1);
        let _ = std::fs::remove_file(&path);
    }
}
