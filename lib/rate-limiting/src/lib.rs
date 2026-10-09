//! The limits a process puts on itself, so that load it cannot serve is
//! refused instead of taking it down.
//!
//! - [`ConcurrencyLimit`] caps how many of something are in use at once.
//! - [`TokenBucket`] caps how often something happens: a rate with a burst.
//! - [`KeyedBuckets`] caps how often something happens per key (a client
//!   address, a tenant), remembering as many keys as it is sized for.
//!
//! What is here counts and caps. Where a limit applies (a connection being
//! accepted, a request being admitted) and what a refusal leads to is
//! decided by whoever holds it.

mod concurrency;
mod keyed_buckets;
mod token_bucket;

pub use concurrency::{ConcurrencyLimit, LimitReached, Permit};
pub use keyed_buckets::KeyedBuckets;
pub use token_bucket::{InvalidBucket, RateLimited, TokenBucket};
