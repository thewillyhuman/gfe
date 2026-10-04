//! Which backends are alive: probes, a per-backend state machine, a checker
//! that runs them, and the health map it keeps up to date for whoever
//! chooses a backend.

pub mod checker;
pub mod health_map;
pub mod probe;
pub mod state_machine;

pub use checker::HealthChecker;
pub use health_map::{HealthMap, HealthStatus};
pub use probe::{make_probe, HttpProbe, Probe, ProbeResult, TcpProbe};
pub use state_machine::BackendHealth;
