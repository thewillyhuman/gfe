//! What applying a dynamic config can fail at.

use gfe_config::ConfigError;
use netkit_load_balancing::PoolError;
use netkit_tls::TlsError;
use std::path::PathBuf;
use thiserror::Error;

/// Why a dynamic config was not applied, or why the node could not start
/// following one. Each message names the file, listener, certificate or
/// pool at fault: the running config is kept, and an operator has the
/// message alone to fix the new one.
#[derive(Debug, Error)]
pub enum ReloadError {
    /// The file could not be read, is not a dynamic config, or is not a
    /// valid one.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// A certificate it names could not be loaded.
    #[error(transparent)]
    Certificates(#[from] TlsError),
    /// A pool could not be built.
    #[error(transparent)]
    Pools(#[from] PoolError),
    /// A listener it adds could not be bound. The message names the
    /// listener and the address.
    #[error("{0}")]
    Bind(std::io::Error),
    /// The deployed config could not be used at start, nor the
    /// last-known-good cache.
    #[error("{deployed}; and the last-known-good cache {} is unusable too: {cache}", path.display())]
    NeitherUsable {
        deployed: Box<ReloadError>,
        path: PathBuf,
        cache: Box<ReloadError>,
    },
    /// The dynamic config file cannot be watched for changes.
    #[error("watching {} for changes: {error}", path.display())]
    Watch { path: PathBuf, error: notify::Error },
}
