//! Which backends are alive: probes, a per-backend state machine, a checker
//! that runs them, and the health map it keeps up to date for whoever
//! chooses a backend.
//!
//! It records no metric: the checker tells its caller what happened through
//! a [`HealthObserver`], and the caller keeps its own metrics from that.

mod checker;
mod health_map;
#[cfg(test)]
mod mock_backend;
mod probe;
mod state_machine;

pub use checker::{CheckSpec, CheckedPool, HealthChecker, HealthObserver};
pub use health_map::{HealthMap, HealthStatus};
pub use probe::{GrpcProbe, HttpProbe, Probe, ProbeKind, ProbeResult, TcpProbe, make_probe};
pub use state_machine::BackendHealth;
