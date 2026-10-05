//! Which backends are alive: probes, a per-backend state machine, a checker
//! that runs them, and the health map it keeps up to date for whoever
//! chooses a backend.

mod checker;
mod health_map;
#[cfg(test)]
mod mock_backend;
mod probe;
mod state_machine;

pub use checker::HealthChecker;
pub use health_map::{HealthMap, HealthStatus};
pub use probe::{GrpcProbe, HttpProbe, Probe, ProbeResult, TcpProbe, make_probe};
pub use state_machine::BackendHealth;
