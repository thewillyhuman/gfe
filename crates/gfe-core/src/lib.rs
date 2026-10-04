//! What every other GFE crate builds on.
//!
//! The configuration of a node ([`config`]) and the error the crates that
//! read and apply it report ([`GfeError`]).

pub mod config;
pub mod error;

pub use error::GfeError;
