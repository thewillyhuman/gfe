//! L7 route matching: `(listener, host, path)` → a compiled route action.
//!
//! The [`RouteTable`] is built once per config reload and is immutable
//! thereafter, so the proxy reads it lock-free behind an `ArcSwap`.

pub mod matcher;
pub mod snapshot;

pub use matcher::{host_matches, path_prefix_matches};
pub use snapshot::{CompiledRoute, RouteTable};
