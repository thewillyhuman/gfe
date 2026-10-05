//! The last-known-good cache of the dynamic config: the last config the
//! node applied, so that a node restarted while its deployed config is
//! missing or broken serves what it served before.
//!
//! The cache is a dynamic config file like any other, so it is read with
//! [`gfe_config::load_dynamic_config`].

use gfe_config::DynamicConfig;
use std::io;
use std::path::Path;

/// Write `config` to `path`, atomically: a reader (a node starting at the
/// same moment) sees the old cache or the new one, never half of one.
pub(crate) fn write(path: &Path, config: &DynamicConfig) -> io::Result<()> {
    let json = serde_json::to_vec_pretty(config).map_err(io::Error::other)?;
    let staged = path.with_extension("tmp");
    std::fs::write(&staged, json)?;
    std::fs::rename(&staged, path)
}

#[cfg(test)]
#[path = "cache_test.rs"]
mod tests;
