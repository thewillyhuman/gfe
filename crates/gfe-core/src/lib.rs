//! What every other GFE crate builds on.
//!
//! The configuration of a node, with how it is read and checked ([`config`]);
//! terminating TLS, from the certificate files to the handshake ([`tls`]);
//! serving the connections of clients ([`server`]); talking to backends
//! ([`upstream`]); and the error the crates that read and apply a config
//! report ([`GfeError`]).
//!
//! What happens to a request between the two sides is not here: the core
//! hands every request to whoever was given to it to answer them.

pub mod config;
pub mod error;
pub mod server;
pub mod tls;
pub mod upstream;

pub use error::GfeError;
