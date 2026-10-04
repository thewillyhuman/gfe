//! Applying a dynamic config to a running node: compiling it into the
//! snapshots the proxy serves from and swapping them in, watching the file
//! and the certificates it names, and the last-known-good cache.

pub mod applier;
pub mod cache;
pub mod cert_files;
pub mod watcher;

pub use applier::{apply, install, prepare, Prepared};
pub use cert_files::CertFiles;
pub use watcher::spawn_watcher;
