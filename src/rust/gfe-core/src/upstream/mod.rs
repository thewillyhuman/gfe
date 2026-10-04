//! The upstream leg: the pooled client a node talks to its backends with, the
//! cap on the connections it may hold open to them, and why a request to one
//! failed.
//!
//! Which backend a request goes to is not decided here.

pub mod client;
pub mod failure;
pub mod limit;

pub use client::{BoxError, KeepAlive, ReqBody, UpstreamClient, UpstreamClientOptions};
pub use failure::{FailureKind, UpstreamFailure};
