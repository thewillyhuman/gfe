//! Telling the node to drain.
//!
//! One watch channel tells the accept loops to stop accepting and the open
//! connections to ask their clients to leave, and the `draining` flag of
//! [`Shared`] makes the ops endpoint fail `/readyz`. The connections get
//! until the drain deadline to finish
//! ([`Listeners::serve_until_drained`](crate::listener::Listeners::serve_until_drained)).

use crate::listener::Shared;
use tokio::sync::watch;

/// The node's shutdown signal: `false` while serving, `true` once draining.
#[derive(Debug)]
pub struct Drain {
    tx: watch::Sender<bool>,
}

impl Drain {
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(false);
        Drain { tx }
    }

    /// A receiver for the listeners, and through them every connection, to
    /// watch.
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.tx.subscribe()
    }

    /// Begin draining: fail readiness, tell accept loops to stop and open
    /// connections to wind down. Calling it again changes nothing.
    pub fn trigger(&self, shared: &Shared) {
        shared.start_draining();
        self.tx.send_replace(true);
    }
}

impl Default for Drain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "drain_test.rs"]
mod tests;
