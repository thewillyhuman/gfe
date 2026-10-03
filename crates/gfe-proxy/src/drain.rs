//! Graceful drain coordination.
//!
//! A watch channel tells the accept loops to stop accepting, and a `draining`
//! flag makes the ops server fail `/readyz`. Connections already open finish
//! on their own, bounded by the drain deadline
//! ([`ListenerSet::serve_until_drained`](crate::ListenerSet::serve_until_drained)).

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

    /// A receiver for the listeners to watch.
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.tx.subscribe()
    }

    /// Begin draining: fail readiness and tell accept loops to stop.
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
