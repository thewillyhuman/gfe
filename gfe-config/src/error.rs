//! What reading or validating a config can fail at.

use std::path::PathBuf;
use thiserror::Error;

/// Why a config was refused. Each message names the file (or, for a dynamic
/// config being validated, the listener, route or pool) and the key at
/// fault, so that the config can be fixed from the message alone.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("reading {}: {error}", path.display())]
    Read {
        path: PathBuf,
        error: std::io::Error,
    },
    /// The file is not TOML or JSON, or does not match the schema (an
    /// unknown key, a missing one, a value of the wrong type).
    #[error("parsing {}: {reason}", path.display())]
    Parse { path: PathBuf, reason: String },
    /// The bootstrap config matches the schema but a value makes no sense.
    #[error("{}: {reason}", path.display())]
    InvalidNodeConfig { path: PathBuf, reason: String },
    /// The dynamic config matches the schema but does not make sense as a
    /// whole (a duplicate id, a dangling reference, ...).
    #[error("invalid dynamic config: {0}")]
    InvalidDynamicConfig(String),
}
