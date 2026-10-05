//! Serving the connections of clients: the listening sockets and their
//! accept loops, TLS termination, the client-side timeouts and limits, what
//! is counted and logged about every connection, and draining.
//!
//! What a request is answered with is not decided here: an established
//! connection is handed to a Pingora application, and what is known about
//! the connection is kept in [`Connections`] for that application to find.

mod conn_info;

pub use conn_info::{ConnInfo, Connections, Registration, RequestGuard};
