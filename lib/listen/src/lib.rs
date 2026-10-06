//! The listening side of a networked system: everything between "the
//! config names an address" and "here is an accepted TCP connection, serve
//! it", draining included.
//!
//! Each accepted connection is handed to the caller's [`Serve`], in a task
//! of its own, with what the caller attached to its listener and a view of
//! the drain signal ([`Accepted`]). A connection over one of the
//! [`Limits`] is closed as soon as it is accepted and reported to the same
//! `Serve` instead. [`serve_plain`] does this for one socket under one cap,
//! for a process's own small endpoints.
//!
//! A process that drains is told so once, by a [`Drain`]: every accept
//! loop and every connection watches it. A connection's bytes on the wire
//! can be counted by wrapping its stream in a [`Metered`].
//!
//! This crate knows nothing of TLS, HTTP, metrics or config files. It
//! reports what happened through return values and through the code its
//! caller gives it; the caller turns that into its own logs and metrics.
mod accept;
mod drain;
mod metered;

#[cfg(test)]
mod test_support;

pub use accept::{Accepted, Limit, Limits, Serve, serve_plain};
pub use drain::Drain;
pub use metered::{Meter, Metered};
