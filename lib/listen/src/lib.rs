//! The listening side of a networked system: everything between "the
//! config names an address" and "here is an accepted TCP connection, serve
//! it", draining included.
//!
//! # The life of a listening socket
//!
//! A process's listening sockets are a [`Listeners`] set, keyed by the
//! address each is configured on. Each time the config changes, the caller
//! [stages](Listeners::stage) the addresses it names, each with what the
//! caller attaches to that listener (`T`: a name, whether it terminates
//! TLS). Staging binds what is new and is the only step that can fail;
//! [committing](Listeners::commit) then starts accepting on the new
//! sockets, closes the ones no longer named, and swaps the attached `T` of
//! the ones kept. A socket whose address does not change is never closed or
//! rebound, so a reload loses no connection.
//!
//! # The life of an accepted connection
//!
//! Each listening socket has an accept loop. A connection it accepts is
//! counted under the [`Limits`]: one over the total or the per-listener cap
//! is closed at once and reported to [`Serve::refused`]. Every other one is
//! handed to [`Serve::serve`] in a task of its own, as an [`Accepted`]: the
//! stream, both addresses, the listener's `T` as it is now, and the drain
//! signal. What happens on the connection (TLS, HTTP, timeouts, logs,
//! metrics) is the caller's; [`Metered`] counts its bytes on the wire.
//! [`serve_plain`] does
//! the same for one socket under one cap, for a process's own small
//! endpoints.
//!
//! When the process drains ([`Drain::trigger`]), the accept loops stop and
//! every connection sees the signal, to ask its client to leave.
//! [`Listeners::serve_until_drained`] waits for the connections to end, up
//! to a deadline, then cuts what is left by dropping its `serve` future.
//!
//! # Replacing the process without closing its sockets
//!
//! A closed listening socket refuses connections and resets the ones
//! waiting in its queue, so a process replaced in place hands its sockets
//! over instead. The running process [lends](Listeners::sockets) duplicates
//! of them and passes them to its successor over a Unix socket. The
//! successor [adopts](Listeners::adopt) them before its first stage, and so
//! accepts on the very sockets the clients are queued on. Once it says it
//! does, the old process drains.
//!
//! This crate knows nothing of TLS, HTTP, metrics or config files. It
//! reports what happened through return values and through the code its
//! caller gives it; the caller turns that into its own logs and metrics.
mod accept;
mod drain;
mod listeners;
mod metered;

#[cfg(test)]
mod test_support;

pub use accept::{Accepted, Limit, Limits, Serve, serve_plain};
pub use drain::Drain;
pub use listeners::{Drained, Listeners, Staged};
pub use metered::{Meter, Metered};
