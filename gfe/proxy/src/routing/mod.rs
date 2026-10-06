//! Which route a request takes: `(listener, host, path)` matched against a
//! table compiled from the dynamic config.
//!
//! The [`RouteTable`] is built once per config reload and is immutable
//! thereafter, so the proxy reads it lock-free behind an `ArcSwap`.

mod matcher;
mod table;

pub use matcher::{host_matches, path_prefix_matches};
pub use table::{CompiledRoute, RouteTable};
