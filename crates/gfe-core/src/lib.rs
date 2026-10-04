//! What every other GFE crate builds on.
//!
//! The configuration of a node, with how it is read and checked ([`config`]);
//! terminating TLS, from the certificate files to the handshake ([`tls`]);
//! talking to backends ([`upstream`]); and the error the crates that read and
//! apply a config report ([`GfeError`]).

pub mod config;
pub mod error;
pub mod tls;
pub mod upstream;

pub use error::GfeError;
