//! The dynamic config: what a node serves, reloaded while it runs.

use crate::{CertEntry, Listener, Route, UpstreamPool};
use serde::{Deserialize, Serialize};

/// The hot-reloadable configuration: certificates, listeners, routes, pools.
///
/// It is read from JSON, and written back to JSON as the last-known-good
/// cache, so every field serializes to what it was read from.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicConfig {
    #[serde(default)]
    pub certificates: Vec<CertEntry>,
    #[serde(default)]
    pub listeners: Vec<Listener>,
    #[serde(default)]
    pub routes: Vec<Route>,
    #[serde(default)]
    pub pools: Vec<UpstreamPool>,
}

#[cfg(test)]
#[path = "dynamic_test.rs"]
mod tests;
