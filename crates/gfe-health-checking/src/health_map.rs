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

    #[test]
    fn only_a_healthy_backend_is_selectable() {
        assert!(HealthStatus::Healthy.is_selectable());
        assert!(!HealthStatus::Draining.is_selectable());
        assert!(!HealthStatus::Unhealthy.is_selectable());
        assert!(!HealthStatus::Unknown.is_selectable());
    }
}
