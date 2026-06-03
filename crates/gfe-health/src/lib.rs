//! L7 backend health checking: probes, a per-backend state machine, and a
//! checker that writes committed transitions to the shared health map.

pub mod checker;
pub mod probe;
pub mod state_machine;

pub use checker::HealthChecker;
pub use probe::{make_probe, HttpProbe, Probe, ProbeResult, TcpProbe};
pub use state_machine::BackendHealth;
