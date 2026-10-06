//! What the kernel knows about the TCP connections of the process that
//! loads this crate, and the process itself, in user space, cannot see: how
//! long a connection waited to be accepted, its round-trip time, its
//! retransmissions, and how it ended.
//!
//! A small eBPF program (`bpf/tcp_events.bpf.c`) is attached to the cgroup
//! the process runs in. It observes sockets, not packets, so it sees the
//! connections the process accepts and the ones it opens the same way,
//! however traffic reaches it.
//!
//! On Linux the program is always built in (the build fails without clang);
//! attaching it still needs the privileges to load eBPF (`CAP_BPF` and
//! `CAP_NET_ADMIN`), a recent enough kernel and cgroup v2. A process that
//! cannot attach it gets the reason from [`TcpProbe::attach`] and can go on
//! without it: observability failing need not become an availability
//! failure. On other operating
//! systems the crate builds as a stand-in that never attaches, so that
//! development there keeps working.
//!
//! The kernel program is C, checked by the kernel's verifier before it runs.
//! This crate contains no `unsafe`: it exchanges plain bytes with the
//! program and decodes them field by field (see `wire.rs`).

// Outside Linux, only the tests decode anything.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod wire;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod imp;

#[cfg(not(target_os = "linux"))]
#[path = "unsupported.rs"]
mod imp;

pub use imp::{ClosedConnections, TcpProbe};

use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;

/// Which end opened a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// This process accepted it: a client connection.
    Accepted,
    /// This process opened it: a connection to a backend.
    Connected,
}

/// How a connection ended, read from the TCP state it was closed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// The peer closed first and this process followed.
    PeerClosed,
    /// This process closed first.
    NodeClosed,
    /// There was no orderly shutdown: a reset in either direction, or the
    /// kernel giving up on a peer that stopped answering.
    Aborted,
    /// A state this crate does not classify.
    Other,
}

/// A TCP connection of this process that has closed, as the kernel saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedConnection {
    /// This process's end.
    pub local: SocketAddr,
    /// The other end: a client, or a backend.
    pub peer: SocketAddr,
    pub origin: Origin,
    pub ending: Ending,
    /// From the completed handshake to the close.
    pub lifetime: Duration,
    /// Smoothed round-trip time at the moment of closing.
    pub rtt: Duration,
    /// The lowest round-trip time measured.
    pub min_rtt: Duration,
    /// Segments retransmitted to the peer.
    pub retransmits: u32,
    /// Segments sent to the peer, retransmissions included.
    pub segments_sent: u32,
    /// Bytes sent and acknowledged by the peer, as TCP counts them: the
    /// handshake and the closing FIN each count as one.
    pub bytes_acked: u64,
    /// Bytes received from the peer, counted the same way.
    pub bytes_received: u64,
}

/// Why the kernel's view cannot be attached. The caller reports it and
/// carries on without the view.
#[derive(Debug, Error)]
pub enum Unavailable {
    #[error("eBPF is only available on Linux")]
    NotLinux,
    #[error("cannot tell which cgroup the node runs in: {0}")]
    Cgroup(String),
    #[error("not permitted to load eBPF (it needs CAP_BPF and CAP_NET_ADMIN): {0}")]
    NotPermitted(String),
    #[error("the kernel rejected the eBPF program: {0}")]
    Kernel(String),
}
