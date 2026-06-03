//! Graceful drain coordination.
//!
//! Phase 1 provides the shutdown signal plumbing: a watch channel that tells
//! accept loops to stop accepting, plus a `draining` flag the ops server uses
//! to fail `/readyz`. In-flight connections finish on their own; Phase 2 adds
//! the drain deadline and upstream connection close-out.

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

    /// A receiver for an accept loop / engine to watch.
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
