//! Keeping a running node in step with its dynamic config: compiling the
//! config into the snapshots the proxy serves from and swapping them in
//! ([`applier`]), and doing so again whenever the file or a certificate it
//! names changes, with a last-known-good cache to start from
//! ([`Controller`]).

pub mod applier;
pub mod cache;
pub mod cert_files;
pub mod orchestrator;
pub mod watcher;

pub use applier::{apply, install, prepare, Prepared};
pub use cert_files::CertFiles;
pub use orchestrator::Controller;
pub use watcher::spawn_watcher;
