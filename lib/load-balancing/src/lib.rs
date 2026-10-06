//! Upstream pools and load-balancing policy: which backend, among the
//! healthy ones of a pool, gets a request.
//!
//! Pure selection logic: no HTTP, no I/O. A [`PoolSet`] is built from the
//! dynamic config's pools and swapped whole on reload; each [`Pool`] picks a
//! backend over the live [`HealthMap`](netkit_health_checking::HealthMap) on
//! every call, and counts what is in flight for `least_request` and for its
//! `max_in_flight` quota.
//!
//! Pingora's own load-balancing crate is not used: its backends are resolved
//! socket addresses, while a GFE backend is a `host:port` that may be a name,
//! and it has no least-request policy.

mod error;
pub mod policy;
mod pool;

pub use error::PoolError;
pub use pool::{InflightGuard, Pool, PoolSet, Selection};
