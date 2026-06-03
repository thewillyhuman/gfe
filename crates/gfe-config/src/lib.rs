//! Config loading, validation, and atomic application.
//!
//! Phase 1: load (TOML bootstrap + JSON dynamic), validate, and apply (compile
//! snapshots + atomic swap). Phase 2 adds the inotify watcher, debounce, and
//! last-known-good cache.

pub mod applier;
pub mod cache;
pub mod loader;
pub mod validator;
pub mod watcher;

pub use applier::apply;
pub use loader::{load_dynamic_config, load_node_config};
pub use validator::validate;
pub use watcher::spawn_watcher;
