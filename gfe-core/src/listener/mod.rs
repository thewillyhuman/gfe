//! Serving the connections of clients: the listening sockets and their
//! accept loops, TLS termination, the client-side timeouts and limits, what
//! is counted and logged about every connection, and draining.
//!
//! What a request is answered with is not decided here: an established
//! connection is handed to a Pingora application (`ServerApp`), and what is
//! known about the connection is kept in [`Connections`] for that
//! application to find.
//!
//! - [`Listeners`] serves the proxy's listeners: bound and released as the
//!   config changes, every connection accounted for (metrics and a
//!   `gfe::conn` event), and drained when [`Drain`] says so.
//! - [`serve_plain`] serves one socket and nothing more, for the node's own
//!   endpoints.
//!
//! What the edge expects of the application:
//!
//! - It tells the connection when each request begins and ends
//!   ([`ConnInfo::begin_request`]), looking the connection up by the
//!   session's `client_addr()` and `server_addr()`. The client timeouts and
//!   the close reasons rest on it.
//! - While [`Shared::is_draining`], it ends keep-alive on the HTTP/1
//!   responses it writes. Pingora does so by itself only for requests that
//!   arrive after the drain began; a request already in flight would
//!   otherwise be answered with `Connection: keep-alive`.

mod acceptor;
mod activity;
mod conn_info;
mod conn_record;
mod connection;
mod drain;
mod listeners;
mod shared;
mod stream;
#[cfg(test)]
mod test_support;

pub use acceptor::serve_plain;
pub use conn_info::{ConnInfo, Connections, Registration, RequestGuard};
pub use drain::Drain;
pub use listeners::{Listeners, Staged};
pub use shared::{AcceptQueue, Shared};
