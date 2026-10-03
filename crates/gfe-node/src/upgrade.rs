//! Replacing a running node in place, without closing its listening sockets.
//!
//! The node that takes over is started by the one it replaces, with
//! `--upgrade` and, as its standard input, a Unix socket to it. Over that
//! socket it is given the listening sockets ([`gfe_handover`]); once it
//! accepts connections on them it says so, and the node it replaces stops.

use anyhow::Result;
use std::net::{SocketAddr, TcpListener};

/// The listening sockets a node starts with. None, unless it takes over from
/// a running node.
#[derive(Default)]
pub struct Inherited {
    /// The proxy's sockets, each with the address its listener is configured
    /// on.
    pub listeners: Vec<(SocketAddr, TcpListener)>,
    /// The socket of the ops server, with the address it is configured on.
    pub ops: Option<(SocketAddr, TcpListener)>,
}

/// The running node this process takes over from, which goes on serving
/// until it is told that it may stop.
pub struct Predecessor {
    #[cfg(unix)]
    channel: std::os::unix::net::UnixStream,
}

impl Predecessor {
    /// Tell the predecessor that this node accepts connections, so that it
    /// stops doing so and winds down.
    pub fn release(self) -> std::io::Result<()> {
        #[cfg(unix)]
        gfe_handover::confirm(&self.channel)?;
        Ok(())
    }
}

/// Take the listening sockets from the node that started this process, which
/// passes them on standard input.
#[cfg(unix)]
pub fn take_over() -> Result<(Predecessor, Inherited)> {
    use anyhow::Context;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    let stdin = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .context("duplicating standard input")?;
    let channel = UnixStream::from(stdin);
    let sockets = gfe_handover::receive(&channel)
        .context("receiving the listening sockets of the running node")?;
    let inherited = Inherited {
        listeners: sockets.listeners,
        ops: sockets.ops,
    };
    Ok((Predecessor { channel }, inherited))
}

#[cfg(not(unix))]
pub fn take_over() -> Result<(Predecessor, Inherited)> {
    anyhow::bail!("--upgrade is not supported on this platform")
}
