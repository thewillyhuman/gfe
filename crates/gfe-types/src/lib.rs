//! Canonical domain types for General Front End (GFE).
//!
//! Pure data + serde, no I/O and no frameworks. This crate is the root of the
//! workspace dependency DAG: every other crate depends on it, and it depends
//! on nothing in the workspace.

pub mod config;
pub mod duration;
pub mod error;
pub mod listener;
pub mod route;
pub mod tls;
pub mod upstream;

pub use config::{
    ControlPlaneConfig, DynamicConfig, HealthCheckConfig, LimitsConfig, NodeConfig, NodeSection,
    ProbeType, TimeoutsConfig, UpstreamConfig,
};
pub use error::GfeError;
pub use listener::{ListenProtocol, Listener, ListenerId};
pub use route::{FixedAction, RedirectAction, Route, RouteAction, RouteId};
pub use tls::{CertEntry, MinVersion, TlsConfig};
pub use upstream::{HealthStatus, LbPolicy, PoolId, Scheme, Upstream, UpstreamPool};
