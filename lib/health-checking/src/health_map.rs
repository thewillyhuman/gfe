//! Shared backend health state: written by the [`HealthChecker`] as probes
//! come back, read on every upstream selection.
//!
//! Selection asks about every backend of a pool on every request, so it
//! must not look backends up: a pool takes a [`HealthHandle`] per backend
//! when it is built and reads it from then on, one atomic load each. The
//! map hands the handles out and is what the checker writes to.
//!
//! [`HealthChecker`]: crate::HealthChecker

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

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

    /// How the status is kept in a [`HealthHandle`].
    fn as_u8(self) -> u8 {
        match self {
            HealthStatus::Unknown => 0,
            HealthStatus::Healthy => 1,
            HealthStatus::Unhealthy => 2,
            HealthStatus::Draining => 3,
        }
    }

    /// The inverse of [`HealthStatus::as_u8`]; anything else is `Unknown`.
    fn from_u8(status: u8) -> HealthStatus {
        match status {
            1 => HealthStatus::Healthy,
            2 => HealthStatus::Unhealthy,
            3 => HealthStatus::Draining,
            _ => HealthStatus::Unknown,
        }
    }
}

/// The health of one backend, shared by the map the checker writes and the
/// pools that read it. Reading is one atomic load: a pool holds a handle
/// per backend and asks on every request without looking anything up.
#[derive(Debug)]
pub struct HealthHandle {
    status: AtomicU8,
    /// Whether a backend not probed yet may receive requests (see
    /// [`HealthMap::new`]).
    unknown_is_selectable: bool,
}

impl HealthHandle {
    fn new(unknown_is_selectable: bool) -> Self {
        HealthHandle {
            status: AtomicU8::new(HealthStatus::Unknown.as_u8()),
            unknown_is_selectable,
        }
    }

    /// The backend's status, as last recorded.
    pub fn status(&self) -> HealthStatus {
        HealthStatus::from_u8(self.status.load(Ordering::Relaxed))
    }

    fn set(&self, status: HealthStatus) {
        self.status.store(status.as_u8(), Ordering::Relaxed);
    }

    /// Whether the backend may receive new requests: it is healthy, or not
    /// probed yet on a map that trusts the unknown.
    pub fn is_selectable(&self) -> bool {
        match self.status() {
            HealthStatus::Healthy => true,
            HealthStatus::Unknown => self.unknown_is_selectable,
            HealthStatus::Unhealthy | HealthStatus::Draining => false,
        }
    }
}

/// The health of every backend known, by `(host, port)`.
pub struct HealthMap {
    map: DashMap<(String, u16), Arc<HealthHandle>>,
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

    /// The handle on the health of the backend at `host:port`: what
    /// [`set`](HealthMap::set) writes to from then on, so a pool that keeps
    /// it sees every change. A backend not recorded yet is `Unknown`.
    pub fn handle(&self, host: &str, port: u16) -> Arc<HealthHandle> {
        let handle = self
            .map
            .entry((host.to_string(), port))
            .or_insert_with(|| Arc::new(HealthHandle::new(self.assume_healthy_when_unknown)));
        Arc::clone(&handle)
    }

    /// Record a backend's health status; every handle on it sees it.
    pub fn set(&self, host: &str, port: u16, status: HealthStatus) {
        self.handle(host, port).set(status);
    }

    /// Current status, defaulting to `Unknown` when unrecorded.
    pub fn get(&self, host: &str, port: u16) -> HealthStatus {
        self.map
            .get(&(host.to_string(), port))
            .map_or(HealthStatus::Unknown, |handle| handle.status())
    }

    /// Whether the backend at `host:port` may receive new requests. For
    /// whoever asks now and then; a pool reads its handles instead.
    pub fn is_selectable(&self, host: &str, port: u16) -> bool {
        self.map
            .get(&(host.to_string(), port))
            .map_or(self.assume_healthy_when_unknown, |handle| {
                handle.is_selectable()
            })
    }

    /// Forget the backends not in `keep` (called when the pools change, so
    /// that removed backends do not linger). A handle on a forgotten
    /// backend stays readable, frozen at its last status, until the pool
    /// holding it is dropped.
    pub fn retain(&self, keep: &[(String, u16)]) {
        self.map.retain(|k, _| keep.contains(k));
    }

    /// How many backends are known: recorded, or handed out to a pool.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether no backend is known.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
#[path = "health_map_test.rs"]
mod tests;
