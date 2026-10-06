//! The parts of the `gfe-node` binary that are reachable from outside it.
//!
//! The binary is the program; this library holds the lifecycle of the
//! process, so that its tests can speak to it directly: the signals a node
//! acts on ([`signals`]), what it tells systemd ([`systemd`]), and replacing
//! a running node in place ([`upgrade`]) by handing its listening sockets to
//! its successor ([`handover`]).

#[cfg(unix)]
pub mod handover;
pub mod signals;
pub mod systemd;
pub mod upgrade;
