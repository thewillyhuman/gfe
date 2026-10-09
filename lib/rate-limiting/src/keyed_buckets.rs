//! A cap on how often something happens, per key: a token bucket for each
//! client address, each tenant, each name, as many as the table is sized
//! for.
//!
//! The table remembers a key for as long as remembering it makes a
//! difference. A bucket that has refilled completely is the bucket of a key
//! never seen, so when the table is full such keys are forgotten to make
//! room; and when none can be, a new key is let through without being
//! counted, rather than every newcomer being refused because of how many
//! others there are. How often that happened is [`untracked`].
//!
//! Like [`TokenBucket`](crate::TokenBucket), it keeps no clock: the caller
//! says what time it is on every call.
//!
//! [`untracked`]: KeyedBuckets::untracked

use crate::token_bucket::{Level, RateLimited};
use std::collections::HashMap;
use std::hash::Hash;
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// How long a full table waits, after looking for keys to forget, before
/// looking again. Looking is a pass over every key: a flood of new keys
/// must not make it happen on each of them.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// So many permits per second for each key, of which up to `burst` may be
/// taken at once, for up to `capacity` keys at a time. Safe to share
/// between threads.
#[derive(Debug)]
pub struct KeyedBuckets<K> {
    per_second: u32,
    burst: u32,
    capacity: usize,
    table: Mutex<Table<K>>,
}

/// The keys remembered, and what the table knows about itself.
#[derive(Debug)]
struct Table<K> {
    levels: HashMap<K, Level>,
    /// When keys to forget were last looked for; `None` until the table
    /// first filled.
    swept_at: Option<Instant>,
    /// Permits given to keys that could not be remembered.
    untracked: u64,
}

impl<K: Hash + Eq> KeyedBuckets<K> {
    /// A table of at most `capacity` keys, each with a full bucket of
    /// `burst` permits when first seen, refilled at `per_second` permits a
    /// second.
    pub fn new(per_second: NonZeroU32, burst: NonZeroU32, capacity: NonZeroUsize) -> Self {
        KeyedBuckets {
            per_second: per_second.get(),
            burst: burst.get(),
            capacity: capacity.get(),
            table: Mutex::new(Table {
                levels: HashMap::new(),
                swept_at: None,
                untracked: 0,
            }),
        }
    }

    /// Take one permit for `key`, as of `now`, unless its bucket is empty.
    ///
    /// A key seen for the first time gets a full bucket, if there is room
    /// for it once the keys that have refilled completely are forgotten;
    /// otherwise it is let through, uncounted. The time between the last
    /// call for `key` and `now` refills its bucket, up to the burst; a
    /// `now` earlier than a previous one refills nothing.
    pub fn try_acquire(&self, key: K, now: Instant) -> Result<(), RateLimited> {
        // The table is consistent between any two statements, so a panic
        // elsewhere while it was held leaves nothing to repair.
        let mut table = self.table.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(level) = table.levels.get_mut(&key) {
            return level.take(now, self.per_second, self.burst);
        }
        if table.levels.len() >= self.capacity {
            self.forget_idle(&mut table, now);
        }
        if table.levels.len() >= self.capacity {
            table.untracked += 1;
            return Ok(());
        }
        let mut level = Level::full(self.burst);
        let taken = level.take(now, self.per_second, self.burst);
        table.levels.insert(key, level);
        taken
    }

    /// How many keys are remembered now.
    pub fn tracked(&self) -> usize {
        self.table().levels.len()
    }

    /// How many permits were given to keys that could not be remembered
    /// because the table was full: so many times the cap was not applied.
    pub fn untracked(&self) -> u64 {
        self.table().untracked
    }

    fn table(&self) -> std::sync::MutexGuard<'_, Table<K>> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Forget the keys whose bucket is full as of `now`, unless that was
    /// done less than [`SWEEP_INTERVAL`] ago.
    fn forget_idle(&self, table: &mut Table<K>, now: Instant) {
        let looked_recently = table
            .swept_at
            .is_some_and(|then| now.saturating_duration_since(then) < SWEEP_INTERVAL);
        if looked_recently {
            return;
        }
        table.swept_at = Some(now);
        let (per_second, burst) = (self.per_second, self.burst);
        table.levels.retain(|_, level| {
            level.refill(now, per_second, burst);
            !level.is_full(burst)
        });
    }
}

#[cfg(test)]
#[path = "keyed_buckets_test.rs"]
mod tests;
