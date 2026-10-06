//! The reverse proxy: serving the connections of clients and proxying their
//! requests to backends.
//!
//! The protocols are the netkit libraries' (HTTP on `netkit-http`, TLS on
//! `netkit-tls`, sockets on `netkit-listen`, and the pools, health checks
//! and kernel view of the others). This crate is what makes them GFE:
//!
//! - [`Frontend`] is a running reverse proxy, all of the below put
//!   together: what a node runs, and what the functional tests drive.
//! - [`edge`] owns the client connections: the listening sockets, TLS
//!   termination, what is counted and logged about every connection, and
//!   draining. Each request is handed to a request handler from there.
//! - [`routing`] decides which route a request takes.
//! - [`handler`] is what happens to a request: its host, its route, the
//!   backend it is forwarded to, and what is counted and logged about it.
//! - [`reload`] keeps a node in step with its dynamic config.
//! - [`kernel`] turns the kernel's view of the node's TCP connections into
//!   metrics and log events.
//! - [`metrics`] defines every metric a node exports.
//!
//! The edge and the handler know each other only through
//! [`edge::RequestHandler`] and [`edge::ConnInfo`]: one knows sockets, the
//! other requests.

pub mod edge;
mod frontend;
pub mod handler;
pub mod kernel;
pub mod metrics;
pub mod reload;
pub mod routing;
#[cfg(test)]
mod test_logs;

pub use frontend::{Frontend, StartError};
