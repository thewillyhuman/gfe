//! The configuration of a node, as its two files spell it: the bootstrap
//! config read once at start ([`NodeConfig`], TOML) and the dynamic config
//! that is reloaded while the node runs ([`DynamicConfig`], JSON).
//!
//! The schema is an operational contract: the files are written by
//! configuration management, so every key, default and rule here is kept
//! stable, and unknown keys are rejected. A key that no longer has an effect
//! stays accepted, and [`NodeConfig::deprecations`] says which of them a
//! file sets.
//!
//! The types are pure data and serde. [`load_node_config`] and
//! [`load_dynamic_config`] read the files into them, and [`validate`] says
//! whether a dynamic config makes sense; none of them knows what a config
//! is used for.

mod certificate;
mod duration;
mod dynamic;
mod error;
mod health_check;
mod listener;
mod loader;
mod node;
mod pool;
mod route;
mod tls;
mod validator;

pub use certificate::CertEntry;
pub use dynamic::DynamicConfig;
pub use error::ConfigError;
pub use health_check::{HealthCheckConfig, ProbeType};
pub use listener::{ListenProtocol, Listener, ListenerId};
pub use loader::{load_dynamic_config, load_node_config};
pub use node::{
    ControlPlaneConfig, EbpfConfig, LimitsConfig, LogConfig, NodeConfig, NodeSection,
    TimeoutsConfig, UpstreamConfig,
};
pub use pool::{LbPolicy, PoolId, Scheme, Upstream, UpstreamPool};
pub use route::{FixedAction, RedirectAction, Route, RouteAction, RouteId};
pub use tls::{MinVersion, TlsConfig};
pub use validator::{MAX_UPSTREAM_WEIGHT, MIN_HEADER_BYTES, MIN_HEALTH_CHECK_INTERVAL, validate};
