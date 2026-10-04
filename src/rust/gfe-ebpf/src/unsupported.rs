//! Stand-ins for where the kernel program cannot exist: another operating
//! system, or a Linux build made without clang. Attaching always fails, so
//! neither type is ever constructed.

use crate::{ClosedConnection, Unavailable};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

/// The attached kernel program. Cannot be attached in this build.
pub struct TcpProbe(Infallible);

/// The stream of closed connections. Never produced in this build.
pub struct ClosedConnections(Infallible);

impl TcpProbe {
    /// Always fails in this build, saying why.
    pub fn attach(_connections: u32) -> Result<(TcpProbe, ClosedConnections), Unavailable> {
        if cfg!(target_os = "linux") {
            Err(Unavailable::NotBuilt)
        } else {
            Err(Unavailable::NotLinux)
        }
    }

    pub fn accept_queue_wait(&self, _local: SocketAddr, _peer: SocketAddr) -> Option<Duration> {
        match self.0 {}
    }

    pub fn lost_events(&self) -> u64 {
        match self.0 {}
    }
}

impl ClosedConnections {
    pub async fn next(&mut self) -> Option<ClosedConnection> {
        match self.0 {}
    }
}
