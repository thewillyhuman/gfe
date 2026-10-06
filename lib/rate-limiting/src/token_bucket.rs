//! A cap on how often something happens: so many permits per second, with
//! a burst.
//!
//! The bucket keeps no clock: the caller says what time it is on every
//! call, so that it can use whichever clock it has and tests need none. It
//! starts no timer and never waits; a refused caller decides what to do.

use std::error::Error;
use std::fmt;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// How much of a permit a bucket holds, in billionths: a permit earned over
/// part of a second is kept, not rounded away.
const UNITS_PER_PERMIT: u64 = 1_000_000_000;

/// Why a [`TokenBucket`] could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidBucket {
    /// A rate of zero permits per second would never refill.
    ZeroRate,
    /// A burst of zero would hold no permit at all.
    ZeroBurst,
}

impl fmt::Display for InvalidBucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidBucket::ZeroRate => f.write_str("a token bucket needs a rate above zero"),
            InvalidBucket::ZeroBurst => f.write_str("a token bucket needs a burst above zero"),
        }
    }
}

impl Error for InvalidBucket {}

/// Why a [`TokenBucket`] gave no permit: it is empty until it refills.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimited {
    /// The rate it refills at.
    pub per_second: u32,
    /// The most permits it holds.
    pub burst: u32,
}

impl fmt::Display for RateLimited {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rate of {} per second (burst {}) reached",
            self.per_second, self.burst
        )
    }
}

impl Error for RateLimited {}

/// So many permits per second, of which up to `burst` may be taken at once.
/// It starts full. Safe to share between threads.
#[derive(Debug)]
pub struct TokenBucket {
    per_second: u32,
    burst: u32,
    state: Mutex<State>,
}

/// What a bucket holds, and as of when.
#[derive(Debug)]
struct State {
    /// Permits held, in [`UNITS_PER_PERMIT`]ths.
    units: u64,
    /// When the bucket was last refilled; `None` until it is first asked.
    refilled_at: Option<Instant>,
}

impl TokenBucket {
    /// A full bucket of `burst` permits, refilled at `per_second` permits a
    /// second. Fails if either is zero.
    pub fn new(per_second: u32, burst: u32) -> Result<TokenBucket, InvalidBucket> {
        if per_second == 0 {
            return Err(InvalidBucket::ZeroRate);
        }
        if burst == 0 {
            return Err(InvalidBucket::ZeroBurst);
        }
        Ok(TokenBucket {
            per_second,
            burst,
            state: Mutex::new(State {
                units: u64::from(burst) * UNITS_PER_PERMIT,
                refilled_at: None,
            }),
        })
    }

    /// Take one permit, as of `now`, unless the bucket is empty.
    ///
    /// The time between the last call and `now` refills the bucket, up to
    /// its burst. A `now` earlier than a previous one refills nothing and
    /// does not move the bucket's time back.
    pub fn try_acquire(&self, now: Instant) -> Result<(), RateLimited> {
        // The state is consistent between any two statements, so a panic
        // elsewhere while it was held leaves nothing to repair.
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let elapsed = state
            .refilled_at
            .map_or(Duration::ZERO, |then| now.saturating_duration_since(then));
        if state.refilled_at.is_none_or(|then| now > then) {
            state.refilled_at = Some(now);
        }
        state.units = self.refilled(state.units, elapsed);
        match state.units.checked_sub(UNITS_PER_PERMIT) {
            Some(left) => {
                state.units = left;
                Ok(())
            }
            None => Err(RateLimited {
                per_second: self.per_second,
                burst: self.burst,
            }),
        }
    }

    /// `units` after `elapsed` of refilling, at most a full bucket.
    fn refilled(&self, units: u64, elapsed: Duration) -> u64 {
        let full = u64::from(self.burst) * UNITS_PER_PERMIT;
        // A second earns `per_second` permits, so a nanosecond earns
        // `per_second` billionths of one: units are billionths.
        let earned = elapsed.as_nanos() * u128::from(self.per_second);
        let units = u128::from(units) + earned;
        u64::try_from(units).map_or(full, |units| units.min(full))
    }
}

#[cfg(test)]
#[path = "token_bucket_test.rs"]
mod tests;
