//! Stand-ins for where the kernel program cannot exist: any operating system
//! other than Linux. Attaching always fails, so neither type is ever
//! constructed.

use crate::{ClosedConnection, Unavailable};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

/// The attached kernel program. Cannot be attached on this system.
pub struct TcpProbe(Infallible);

/// The stream of closed connections. Never produced on this system.
pub struct ClosedConnections(Infallible);

impl TcpProbe {
    /// Always fails on this system, saying why.
    pub fn attach(_connections: u32) -> Result<(TcpProbe, ClosedConnections), Unavailable> {
        Err(Unavailable::NotLinux)
    }

    /// Unreachable: there is never a probe to ask.
    pub fn accept_queue_wait(&self, _local: SocketAddr, _peer: SocketAddr) -> Option<Duration> {
        match self.0 {}
    }

    /// Unreachable: there is never a probe to ask.
    pub fn lost_events(&self) -> u64 {
        match self.0 {}
    }
}

impl ClosedConnections {
    /// Unreachable: there is never a stream to read.
    pub async fn next(&mut self) -> Option<ClosedConnection> {
        match self.0 {}
    }
}

#[cfg(test)]
#[path = "unsupported_test.rs"]
mod tests;
