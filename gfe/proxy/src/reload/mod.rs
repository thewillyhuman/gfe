//! Keeping a running node in step with its dynamic config.
//!
//! - [`prepare`] validates a config and compiles it into what the proxy
//!   serves from (certificates, routes, pools) without swapping anything
//!   in: what `--check-config` runs.
//! - [`Controller`] applies the config a node starts from (or its
//!   last-known-good cache), then applies it again whenever the file or a
//!   certificate it names changes. Applying is all or nothing: the sockets
//!   a config adds are bound first, and only then is everything swapped. A
//!   config that fails anywhere leaves the running one untouched, and the
//!   metrics say so (`gfe_config_reload_errors_total`,
//!   `gfe_config_reload_failed`).

mod applier;
mod cache;
mod controller;
mod error;
mod health;
#[cfg(test)]
mod test_support;
mod watcher;

/// For the proxy's unit tests, which build pools without a reload.
#[cfg(test)]
pub(crate) use applier::pool_specs;
pub use applier::{Prepared, prepare};
pub use controller::{CERT_POLL_INTERVAL, Controller};
pub use error::ReloadError;
