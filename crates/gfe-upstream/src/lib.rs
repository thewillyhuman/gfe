//! Upstream pools, load-balancing policy, the shared health map, and the
//! pooled hyper upstream client.

pub mod client;
pub mod health_map;
pub mod policy;
pub mod pool;

pub use client::{BoxError, ReqBody, UpstreamClient, UpstreamClientOptions};
pub use health_map::HealthMap;
pub use pool::{InflightGuard, Pool, PoolSet, Selection};
