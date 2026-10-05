//! The limits a node puts on itself, so that load it cannot serve is refused
//! instead of taking the node down.
//!
//! What is here counts and caps. Where a limit applies (a connection being
//! accepted, a connection to a backend being opened) is decided by whoever
//! holds it.

mod concurrency;

pub use concurrency::{ConcurrencyLimit, LimitReached, Permit};
