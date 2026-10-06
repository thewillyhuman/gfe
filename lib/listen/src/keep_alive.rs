//! Having the kernel probe the peer of a silent connection.
//!
//! A client that vanishes without a FIN or a RST (a machine switched off, a
//! NAT that forgot the flow) leaves its connection open on this side for as
//! long as nothing is written to it, which an HTTP/1 request in flight or
//! an idle keep-alive connection may not do for a long time. TCP keepalive
//! has the kernel probe such a peer and fail the connection when it does
//! not answer. Left to itself the kernel waits two hours before the first
//! probe; this is how a caller says how long instead.
//!
//! The policy (how long, how often, how many) is the caller's. Applying it
//! when a connection is accepted is too: nothing here does it for every
//! connection.

use socket2::{SockRef, TcpKeepalive};
use std::io;
use std::time::Duration;
use tokio::net::TcpStream;

/// Probe the peer of `stream` once it has been silent for `idle`, then every
/// `interval`, and fail the connection (reads and writes then fail with
/// `TimedOut`) after `probes` unanswered probes.
///
/// The kernel counts in whole seconds: `idle` and `interval` lose their
/// fraction, and less than a second of either is refused (`InvalidInput`),
/// as are zero probes; the socket is then left untouched.
pub fn keep_alive(
    stream: &TcpStream,
    idle: Duration,
    interval: Duration,
    probes: u32,
) -> io::Result<()> {
    let second = Duration::from_secs(1);
    if idle < second || interval < second || probes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "tcp keepalive needs at least a second of idle time ({idle:?}) and \
                 between probes ({interval:?}), and at least one probe ({probes})"
            ),
        ));
    }
    let keepalive = TcpKeepalive::new()
        .with_time(idle)
        .with_interval(interval)
        .with_retries(probes);
    SockRef::from(stream).set_tcp_keepalive(&keepalive)
}

#[cfg(test)]
#[path = "keep_alive_test.rs"]
mod tests;
