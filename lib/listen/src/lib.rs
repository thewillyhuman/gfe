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
//! metrics) is the caller's; [`Metered`] counts its bytes on the wire, and
//! [`keep_alive`] has the kernel probe a silent peer. [`serve_plain`] does
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
//! over instead:
//!
//! 1. The running process starts its successor with one end of a Unix
//!    socket pair, [lends](Listeners::sockets) duplicates of its listening
//!    sockets and [sends](handover::send) them over the pair, each with a
//!    role and the address it is configured on. It keeps accepting.
//! 2. The successor [receives](handover::receive) them, which tells the
//!    running process its process id ([`handover::await_receipt`]), and
//!    [adopts](Listeners::adopt) them before its first stage: it accepts on
//!    the very sockets the clients are queued on, without binding.
//! 3. Once it accepts, the successor [confirms](handover::confirm). The
//!    running process ([`handover::await_confirmation`]) then drains: it
//!    stops accepting on its copies and lets its connections finish.
//!
//! Until step 3 the running process has changed nothing: if the successor
//! fails, it goes on serving.
//!
//! This crate knows nothing of TLS, HTTP, metrics or config files. It
//! reports what happened through return values and through the code its
//! caller gives it; the caller turns that into its own logs and metrics.
mod accept;
mod drain;
#[cfg(unix)]
pub mod handover;
mod keep_alive;
mod listeners;
mod metered;

#[cfg(test)]
mod test_support;

pub use accept::{Accepted, Limit, Limits, Serve, serve_plain};
pub use drain::Drain;
pub use keep_alive::keep_alive;
pub use listeners::{Drained, Listeners, Staged};
pub use metered::{Meter, Metered, Tally};
