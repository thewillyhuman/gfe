//! What the kernel knows about the node's TCP connections and the proxy, in
//! user space, cannot see: how long a connection waited to be accepted, its
//! round-trip time, its retransmissions, and how it ended.
//!
//! A small eBPF program (`bpf/tcp_events.bpf.c`) is attached to the cgroup
//! the node runs in. It observes sockets, not packets, so it sees the
//! connections the node accepts and the ones it opens, identically whether
//! traffic reaches the node through a load balancer, a tunnel, or directly.
//!
//! This is strictly optional. Attaching needs Linux, a build made with clang
//! available, and the privileges to load eBPF (`CAP_BPF` and `CAP_NET_ADMIN`).
//! Where any of that is missing, [`TcpProbe::attach`] says so and the caller
//! carries on without it.
//!
//! The kernel program is C, checked by the kernel's verifier before it runs.
//! This crate contains no `unsafe`: it exchanges plain bytes with the
//! program and decodes them field by field (see `wire.rs`).

// Where the kernel program is not built, only the tests decode anything.
#[cfg_attr(not(all(target_os = "linux", gfe_bpf_built)), allow(dead_code))]
mod wire;

#[cfg(all(target_os = "linux", gfe_bpf_built))]
#[path = "linux.rs"]
mod imp;

#[cfg(not(all(target_os = "linux", gfe_bpf_built)))]
#[path = "unsupported.rs"]
mod imp;

pub use imp::{ClosedConnections, TcpProbe};

use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;

/// Which end opened a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The node accepted it: a client connection.
    Accepted,
    /// The node opened it: a connection to a backend.
    Connected,
}

/// How a connection ended, read from the TCP state it was closed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// The peer closed first and the node followed.
    PeerClosed,
    /// The node closed first.
    NodeClosed,
    /// There was no orderly shutdown: a reset in either direction, or the
    /// kernel giving up on a peer that stopped answering.
    Aborted,
    /// A state this crate does not classify.
    Other,
}

/// A TCP connection of the node that has closed, as the kernel saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedConnection {
    /// The node's end.
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

/// Why the kernel's view is not available.
#[derive(Debug, Error)]
pub enum Unavailable {
    #[error("eBPF is only available on Linux")]
    NotLinux,
    #[error("this build has no eBPF program: it was compiled without clang")]
    NotBuilt,
    #[error("cannot tell which cgroup the node runs in: {0}")]
    Cgroup(String),
    #[error("not permitted to load eBPF, which needs CAP_BPF and CAP_NET_ADMIN: {0}")]
    NotPermitted(String),
    #[error("the kernel rejected the eBPF program: {0}")]
    Kernel(String),
}
