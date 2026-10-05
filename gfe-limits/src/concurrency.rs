//! A cap on how many of something are in use at once.

use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Why nothing more could be taken from a [`ConcurrencyLimit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitReached {
    /// The cap that was reached.
    pub max: usize,
}

impl fmt::Display for LimitReached {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "limit of {} reached", self.max)
    }
}

impl Error for LimitReached {}

/// How many of something are in use at once (connections open, requests in
/// flight), and how many may be.
#[derive(Debug)]
pub struct ConcurrencyLimit {
    in_use: AtomicUsize,
    max: Option<usize>,
}

impl ConcurrencyLimit {
    /// A limit of `max` in use at once; `None` counts without limiting.
    pub fn new(max: Option<usize>) -> Arc<Self> {
        Arc::new(ConcurrencyLimit {
            in_use: AtomicUsize::new(0),
            max,
        })
    }

    /// How many are in use now. An attempt that is being refused is counted
    /// until it has been, so this may briefly read above the cap.
    pub fn in_use(&self) -> usize {
        self.in_use.load(Ordering::Relaxed)
    }

    /// The cap, if any.
    pub fn max(&self) -> Option<usize> {
        self.max
    }

    /// Take one more, unless the cap is reached. What was taken is given back
    /// when the permit is dropped.
    pub fn try_acquire(self: &Arc<Self>) -> Result<Permit, LimitReached> {
        let already_in_use = self.in_use.fetch_add(1, Ordering::Relaxed);
        let permit = Permit(self.clone());
        match self.max {
            // Dropping the permit gives back what was just taken.
            Some(max) if already_in_use >= max => Err(LimitReached { max }),
            _ => Ok(permit),
        }
    }
}

/// One share of a [`ConcurrencyLimit`], given back when dropped.
#[derive(Debug)]
pub struct Permit(Arc<ConcurrencyLimit>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.in_use.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
#[path = "concurrency_test.rs"]
mod tests;
