//! Shared backend health state: written by the [`HealthChecker`] as probes
//! come back, read on every upstream selection.
//!
//! [`HealthChecker`]: crate::HealthChecker

use dashmap::DashMap;

/// Health state of a single backend, as the health checker last decided it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HealthStatus {
    /// Not yet probed enough times to decide.
    #[default]
    Unknown,
    /// Receiving traffic.
    Healthy,
    /// Failing checks; excluded from selection.
    Unhealthy,
    /// Lame-duck: excluded from *new* requests, existing ones drain.
    Draining,
}

impl HealthStatus {
    /// Whether a backend in this state may receive new requests.
    pub fn is_selectable(&self) -> bool {
        matches!(self, HealthStatus::Healthy)
    }
}

/// A concurrent map of `(host, port)` → [`HealthStatus`].
pub struct HealthMap {
    map: DashMap<(String, u16), HealthStatus>,
    /// When `true`, a backend with no recorded status is treated as
    /// selectable: a process that has just started serves before its first
    /// probes come back.
    assume_healthy_when_unknown: bool,
}

impl HealthMap {
    /// An empty map. `assume_healthy_when_unknown` says whether a backend
    /// with no recorded status may receive requests.
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

    /// Remove entries not present in `keep` (called when the pools change so
    /// removed backends don't linger).
    pub fn retain(&self, keep: &[(String, u16)]) {
        self.map.retain(|k, _| keep.contains(k));
    }

    /// How many backends have a recorded status.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether no backend has a recorded status.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
#[path = "health_map_test.rs"]
mod tests;
