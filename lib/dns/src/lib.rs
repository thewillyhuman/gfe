//! Turning the name of a host into an address to connect to.
//!
//! A [`Cache`] stands in front of a resolver ([`Resolve`]): an answer is
//! trusted for a fixed time, so that a name used for every connection is
//! not looked up for every connection, and when a refresh fails the last
//! answer is kept, so that a resolver outage does not cut off hosts whose
//! addresses have not changed. IP literals are never looked up. The first
//! address of an answer is the one used.
//!
//! The resolver is the system's ([`SystemResolver`]): names are looked up
//! the way every other program on the machine looks them up (`/etc/hosts`,
//! `resolv.conf`, search domains), and this crate speaks no DNS itself. The
//! system gives no time-to-live with its answers, which is why the cache
//! takes one.
mod cache;

pub use cache::{Cache, Resolve, SystemResolver};
