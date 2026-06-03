//! Shared backend health state.
//!
//! Written by the control plane (`gfe-health`) and read by the data plane on
//! every upstream selection. Lives in this crate because the hot-path reader
//! owns it; the control plane depends on this crate to write it.

use dashmap::DashMap;
use gfe_types::HealthStatus;

/// A concurrent map of `(host, port)` → [`HealthStatus`].
pub struct HealthMap {
    map: DashMap<(String, u16), HealthStatus>,
    /// When `true`, a backend with no recorded status is treated as
    /// selectable. Phase 1 runs with this on (no health checker yet); once a
    /// checker is running it records explicit statuses.
    assume_healthy_when_unknown: bool,
}

impl HealthMap {
    pub fn new(assume_healthy_when_unknown: bool) -> Self {
        HealthMap {
            map: DashMap::new(),
            assume_healthy_when_unknown,
        }
    }

    /// Record a backend's health status.
    pub fn set(&self, host: &str, port: u16, status: HealthStatus) {
        self.map.insert((host.to_string(), port), status);
    }

    /// Current status, defaulting to `Unknown` when unrecorded.
    pub fn get(&self, host: &str, port: u16) -> HealthStatus {
        self.map
            .get(&(host.to_string(), port))
            .map(|e| *e.value())
            .unwrap_or(HealthStatus::Unknown)
    }

    /// Whether a backend may receive new requests.
    pub fn is_selectable(&self, host: &str, port: u16) -> bool {
        match self.map.get(&(host.to_string(), port)) {
            Some(e) => e.value().is_selectable(),
            None => self.assume_healthy_when_unknown,
        }
    }

    /// Remove entries not present in `keep` (called after a config reload so
    /// removed backends don't linger).
    pub fn retain(&self, keep: &[(String, u16)]) {
        self.map.retain(|k, _| keep.contains(k));
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optimistic_unknown() {
        let h = HealthMap::new(true);
        assert!(h.is_selectable("10.0.0.1", 80));
        h.set("10.0.0.1", 80, HealthStatus::Unhealthy);
        assert!(!h.is_selectable("10.0.0.1", 80));
    }

    #[test]
    fn pessimistic_unknown() {
        let h = HealthMap::new(false);
        assert!(!h.is_selectable("10.0.0.1", 80));
        h.set("10.0.0.1", 80, HealthStatus::Healthy);
        assert!(h.is_selectable("10.0.0.1", 80));
    }
}
