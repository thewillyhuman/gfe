//! Passing a node's listening sockets to the process that replaces it, in
//! GFE's terms.
//!
//! The exchange is netkit-listen's ([`netkit_listen::handover`]). What is
//! GFE's is its header, `gfe-handover 1`, and the two roles a socket has:
//! `listener` for the proxy's sockets, `ops` for the ops server's. Both are
//! part of the exchange: a running `v1.1.0` node hands its sockets to a new
//! binary with exactly these words.
//!
//! ```text
//! outgoing node                        successor
//!   gfe-handover 1               →
//!   listener 0.0.0.0:443         →     one line per socket, the socket
//!   ops 127.0.0.1:9101           →     itself travelling with its line
//!   (closes its sending half)    →
//!                                ←     received 4242     its process id
//!                                ←     ready             once it accepts
//! ```

use netkit_listen::handover::{self, Protocol, Socket};
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::os::unix::net::UnixStream;

pub use netkit_listen::handover::{await_confirmation, await_receipt, confirm};

/// The first line of a handover: `gfe-handover 1`.
const PROTOCOL: Protocol = Protocol {
    name: "gfe-handover",
    version: 1,
};

/// The role of a proxy's socket.
const LISTENER: &str = "listener";

/// The role of the ops server's socket.
const OPS: &str = "ops";

/// The listening sockets of a node.
#[derive(Debug, Default)]
pub struct Sockets {
    /// The proxy's sockets, each with the address its listener is configured
    /// on (which is what the successor looks it up by).
    pub listeners: Vec<(SocketAddr, TcpListener)>,
    /// The socket of the ops server, with the address it is configured on.
    pub ops: Option<(SocketAddr, TcpListener)>,
}

/// Give `sockets` to the successor at the other end of `channel`. The
/// sockets stay open here too.
pub fn send(channel: &UnixStream, sockets: &Sockets) -> io::Result<()> {
    let listeners = sockets
        .listeners
        .iter()
        .map(|(addr, socket)| (LISTENER, addr, socket));
    let ops = sockets.ops.iter().map(|(addr, socket)| (OPS, addr, socket));
    // Duplicates, closed once sent: a handed-over socket owns its
    // descriptor, and the node keeps its own until the successor takes over.
    let handed = listeners
        .chain(ops)
        .map(|(role, addr, socket)| {
            Ok(Socket {
                role: role.to_string(),
                addr: *addr,
                socket: socket.try_clone()?,
            })
        })
        .collect::<io::Result<Vec<Socket>>>()?;
    handover::send(channel, &PROTOCOL, &handed)
}

/// Take the sockets the outgoing node at the other end of `channel` gives,
/// and tell it which process has them.
pub fn receive(channel: &UnixStream) -> io::Result<Sockets> {
    let mut sockets = Sockets::default();
    for handed in handover::receive(channel, &PROTOCOL, &[LISTENER, OPS])? {
        let socket = (handed.addr, handed.socket);
        if handed.role == OPS {
            sockets.ops = Some(socket);
        } else {
            sockets.listeners.push(socket);
        }
    }
    Ok(sockets)
}

#[cfg(test)]
#[path = "handover_test.rs"]
mod tests;
