//! A cap on how often something happens: so many permits per second, with
//! a burst.
//!
//! The bucket keeps no clock: the caller says what time it is on every
//! call, so that it can use whichever clock it has and tests need none. It
//! starts no timer and never waits; a refused caller decides what to do.

use std::error::Error;
use std::fmt;
use std::num::NonZeroU32;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// How much of a permit a bucket holds, in billionths: a permit earned over
/// part of a second is kept, not rounded away.
const UNITS_PER_PERMIT: u64 = 1_000_000_000;

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

/// What a bucket holds, and as of when: the arithmetic of a token bucket,
/// without its rate and burst, so that whoever keeps a level per key keeps
/// those once.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Level {
    /// Permits held, in [`UNITS_PER_PERMIT`]ths.
    units: u64,
    /// When the level was last refilled; `None` until it is first asked.
    refilled_at: Option<Instant>,
}

impl Level {
    /// A full level: `burst` permits.
    pub(crate) fn full(burst: u32) -> Level {
        Level {
            units: u64::from(burst) * UNITS_PER_PERMIT,
            refilled_at: None,
        }
    }

    /// Add what the time between the last call and `now` earns at
    /// `per_second`, up to `burst`. A `now` earlier than a previous one
    /// earns nothing and does not move the level's time back.
    pub(crate) fn refill(&mut self, now: Instant, per_second: u32, burst: u32) {
        let elapsed = self
            .refilled_at
            .map_or(Duration::ZERO, |then| now.saturating_duration_since(then));
        if self.refilled_at.is_none_or(|then| now > then) {
            self.refilled_at = Some(now);
        }
        let full = u64::from(burst) * UNITS_PER_PERMIT;
        // A second earns `per_second` permits, so a nanosecond earns
        // `per_second` billionths of one: units are billionths.
        let earned = elapsed.as_nanos() * u128::from(per_second);
        let units = u128::from(self.units) + earned;
        self.units = u64::try_from(units).map_or(full, |units| units.min(full));
    }

    /// Take one permit, as of `now`, unless the level is empty once
    /// refilled.
    pub(crate) fn take(
        &mut self,
        now: Instant,
        per_second: u32,
        burst: u32,
    ) -> Result<(), RateLimited> {
        self.refill(now, per_second, burst);
        match self.units.checked_sub(UNITS_PER_PERMIT) {
            Some(left) => {
                self.units = left;
                Ok(())
            }
            None => Err(RateLimited { per_second, burst }),
        }
    }

    /// Whether the level holds every one of `burst` permits, as of its last
    /// refill: nothing has been taken from it that time has not given back.
    pub(crate) fn is_full(&self, burst: u32) -> bool {
        self.units == u64::from(burst) * UNITS_PER_PERMIT
    }
}

/// So many permits per second, of which up to `burst` may be taken at once.
/// It starts full. Safe to share between threads.
#[derive(Debug)]
pub struct TokenBucket {
    per_second: u32,
    burst: u32,
    level: Mutex<Level>,
}

impl TokenBucket {
    /// A full bucket of `burst` permits, refilled at `per_second` permits a
    /// second. A rate of zero would never refill and a burst of zero would
    /// hold no permit, so neither can be asked for.
    pub fn new(per_second: NonZeroU32, burst: NonZeroU32) -> TokenBucket {
        TokenBucket {
            per_second: per_second.get(),
            burst: burst.get(),
            level: Mutex::new(Level::full(burst.get())),
        }
    }

    /// Take one permit, as of `now`, unless the bucket is empty.
    ///
    /// The time between the last call and `now` refills the bucket, up to
    /// its burst. A `now` earlier than a previous one refills nothing and
    /// does not move the bucket's time back.
    pub fn try_acquire(&self, now: Instant) -> Result<(), RateLimited> {
        // The level is consistent between any two statements, so a panic
        // elsewhere while it was held leaves nothing to repair.
        let mut level = self.level.lock().unwrap_or_else(PoisonError::into_inner);
        level.take(now, self.per_second, self.burst)
    }
}

#[cfg(test)]
#[path = "token_bucket_test.rs"]
mod tests;
