//! The edge: the connections of clients, from the listening socket to the
//! request handed over to be answered.
//!
//! What a request is answered with is not decided here. Every request is
//! handed to a [`RequestHandler`] together with what is known about the
//! connection it arrived on ([`ConnInfo`]).
//!
//! - [`Edge`] serves each connection `netkit_listen` accepts: socket
//!   options, TLS termination, HTTP (`netkit_http`), and the accounting of
//!   the connection, as metrics and one `gfe::conn` event saying why it
//!   closed.
//! - [`Shared`] is what every connection shares: metrics, limits,
//!   timeouts, and what the kernel and the certificate resolver know.
mod conn_info;
mod conn_record;
mod connection;
mod handler;
mod shared;
#[cfg(test)]
mod test_support;

pub use conn_info::ConnInfo;
pub use connection::Edge;
pub use handler::RequestHandler;
pub use shared::{AcceptQueue, Shared};
