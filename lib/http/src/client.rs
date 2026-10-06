//! Requesting: sending requests to servers and receiving their responses.
//!
//! A [`Client`] keeps connections open between requests and reuses them,
//! speaking HTTP/1.1 or HTTP/2 as the [`Scheme`] and the request call for.
//! Opening a connection looks the host's address up (names through a cache,
//! `netkit-dns`), connects TCP with a timeout and `TCP_NODELAY`, and runs
//! TLS when the scheme asks for it (`netkit-tls`), all under one cap on the
//! connections open at once. What went wrong comes back as a [`Failure`] of
//! a [`FailureKind`] the caller acts on.
//!
//! The client sends what it is given: it does not follow redirects, add or
//! strip hop-by-hop headers, retry a request that reached a server, nor
//! bound how long a server may take to answer. Those are the caller's.
mod dial;
mod failure;
mod pool;

pub use failure::{Failure, FailureKind};
pub use pool::{Client, KeepAlive, Options, Scheme};
