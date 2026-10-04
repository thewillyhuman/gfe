//! Upstream pools and load-balancing policy: which backend, among the
//! healthy ones of a pool, gets a request.

pub mod policy;
pub mod pool;

pub use pool::{InflightGuard, Pool, PoolSet, Selection};
