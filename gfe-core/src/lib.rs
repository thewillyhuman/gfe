//! The reverse proxy: serving the connections of clients and proxying their
//! requests to backends.
//!
//! The HTTP engine is Cloudflare's Pingora: its HTTP/1 and HTTP/2
//! implementations on both legs, its proxy state machine, and its pooled,
//! TLS-capable connections to backends. This crate is what a node adds
//! around it:
//!
//! - [`listener`] owns the edge: the listening sockets, TLS termination,
//!   what is counted and logged about every connection, and draining. Each
//!   established connection is handed to Pingora from there.
//! - [`routing`] decides which route a request takes.
//! - [`proxy`] is what happens to a request: Pingora calls into it at every
//!   stage, from the request head to the last byte of the response.
//!
//! The edge is the node's own, rather than Pingora's listening service,
//! because of what a node promises its operators: listeners that come and
//! go with a reload, a count and a reason for every handshake that fails and
//! every connection that closes, and a drain that ends as soon as the last
//! client has left.

pub mod listener;
pub mod proxy;
pub mod routing;
