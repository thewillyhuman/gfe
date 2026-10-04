//! A cap on how many of something are in use at once.

use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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
mod tests {
    use super::*;

    #[test]
    fn takes_up_to_the_cap_and_no_further() {
        let limit = ConcurrencyLimit::new(Some(2));

        let first = limit.try_acquire();
        let second = limit.try_acquire();
        let third = limit.try_acquire();

        assert!(first.is_ok() && second.is_ok());
        assert_eq!(third.unwrap_err(), LimitReached { max: 2 });
        assert_eq!(limit.in_use(), 2);
    }

    #[test]
    fn a_dropped_permit_makes_room_again() {
        let limit = ConcurrencyLimit::new(Some(1));
        let only = limit.try_acquire().unwrap();

        drop(only);

        assert_eq!(limit.in_use(), 0);
        assert!(limit.try_acquire().is_ok());
    }

    #[test]
    fn without_a_cap_everything_is_taken_and_counted() {
        let limit = ConcurrencyLimit::new(None);

        let permits: Vec<_> = (0..1000).map(|_| limit.try_acquire().unwrap()).collect();

        assert_eq!(limit.in_use(), permits.len());
    }

    #[test]
    fn reports_its_cap() {
        assert_eq!(ConcurrencyLimit::new(Some(7)).max(), Some(7));
        assert_eq!(ConcurrencyLimit::new(None).max(), None);
    }
}
