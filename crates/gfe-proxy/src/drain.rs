//! Graceful drain coordination.
//!
//! A watch channel tells the accept loops to stop accepting and the open
//! connections to ask their clients to leave, and a `draining` flag makes the
//! ops server fail `/readyz`. The connections get until the drain deadline to
//! finish ([`ListenerSet::serve_until_drained`](crate::ListenerSet::serve_until_drained)).

use crate::ProxyShared;
use std::sync::atomic::Ordering;
use tokio::sync::watch;

/// Owns the shutdown signal broadcast to all accept loops.
pub struct DrainController {
    tx: watch::Sender<bool>,
}

impl DrainController {
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(false);
        DrainController { tx }
    }

    /// A receiver for the listeners, and through them every connection, to
    /// watch.
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.tx.subscribe()
    }

    /// Begin draining: fail readiness, tell accept loops to stop and open
    /// connections to wind down.
    pub fn trigger(&self, shared: &ProxyShared) {
        shared.draining.store(true, Ordering::SeqCst);
        let _ = self.tx.send(true);
    }
}

impl Default for DrainController {
    fn default() -> Self {
        Self::new()
    }
}
