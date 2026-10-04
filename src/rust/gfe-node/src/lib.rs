//! The parts of the `gfe-node` binary that are reachable from outside it.
//!
//! The binary is the program; this library holds what its tests need to
//! speak to it directly: the exchange a node hands its listening sockets to
//! its successor with ([`handover`]).

#[cfg(unix)]
pub mod handover;
