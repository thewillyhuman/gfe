//! Upstream pools and load-balancing policy: which backend, among the
//! healthy ones of a pool, gets a request.
//!
//! Pure selection logic: no HTTP, no I/O. A [`PoolSet`] is built from
//! [`PoolSpec`]s against a [`HealthMap`](netkit_health_checking::HealthMap)
//! and swapped whole when they change; each [`Pool`] admits a request under
//! its `max_in_flight` quota and its `max_requests_per_second` rate, picks
//! a backend over the live health of its backends on every call, and
//! counts what is in flight for `least_request`. A backend is a `host:port`
//! that may be a name: resolving it is the caller's business.

mod error;
pub mod policy;
mod pool;

pub use error::PoolError;
pub use policy::Policy;
pub use pool::{Backend, InflightGuard, Limit, Pool, PoolSet, PoolSpec, Selection};
