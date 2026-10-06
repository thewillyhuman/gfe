//! The listening side of a networked system: everything between "the
//! config names an address" and "here is an accepted TCP connection, serve
//! it", draining included.
//!
//! A process that drains is told so once, by a [`Drain`]: every accept
//! loop and every connection watches it. A connection's bytes on the wire
//! can be counted by wrapping its stream in a [`Metered`].
//!
//! This crate knows nothing of TLS, HTTP, metrics or config files. It
//! reports what happened through return values and through the code its
//! caller gives it; the caller turns that into its own logs and metrics.
mod drain;
mod metered;

pub use drain::Drain;
pub use metered::{Meter, Metered};
