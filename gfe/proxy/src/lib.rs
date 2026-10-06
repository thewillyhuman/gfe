//! The reverse proxy: serving the connections of clients and proxying their
//! requests to backends.
//!
//! The HTTP engine is Cloudflare's Pingora: its HTTP/1 and HTTP/2
//! implementations on both legs, its proxy state machine, and its pooled,
//! TLS-capable connections to backends. This crate is what a node adds
//! around it:
//!
//! - [`Frontend`] is a running reverse proxy, all of the below put
//!   together: what a node runs, and what the functional tests drive.
//! - [`listener`] owns the edge: the listening sockets, TLS termination,
//!   what is counted and logged about every connection, and draining. Each
//!   established connection is handed to Pingora from there.
//! - [`routing`] decides which route a request takes.
//! - [`proxy`] is what happens to a request: Pingora calls into it at every
//!   stage, from the request head to the last byte of the response.
//! - [`reload`] keeps a node in step with its dynamic config.
//! - [`kernel`] turns the kernel's view of the node's TCP connections into
//!   metrics and log events.
//! - [`metrics`] defines every metric a node exports.
//!
//! The edge is the node's own, rather than Pingora's listening service,
//! because of what a node promises its operators: listeners that come and
//! go with a reload, a count and a reason for every handshake that fails and
//! every connection that closes, and a drain that ends as soon as the last
//! client has left.

mod frontend;
pub mod kernel;
pub mod listener;
pub mod metrics;
pub mod proxy;
pub mod reload;
pub mod routing;

pub use frontend::{Frontend, StartError};
