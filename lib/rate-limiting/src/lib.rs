//! The limits a process puts on itself, so that load it cannot serve is
//! refused instead of taking it down.
//!
//! - [`ConcurrencyLimit`] caps how many of something are in use at once.
//! - [`TokenBucket`] caps how often something happens: a rate with a burst.
//!
//! What is here counts and caps. Where a limit applies (a connection being
//! accepted, a request being admitted) and what a refusal leads to is
//! decided by whoever holds it.

mod concurrency;
mod token_bucket;

pub use concurrency::{ConcurrencyLimit, LimitReached, Permit};
pub use token_bucket::{InvalidBucket, RateLimited, TokenBucket};
