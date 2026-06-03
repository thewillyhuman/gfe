//! Control-plane orchestrator: coordinates config load/apply, health checking,
//! the last-known-good cache, and hot-reload.

pub mod orchestrator;

pub use orchestrator::Controller;
