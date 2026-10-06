//! Telling a process to drain.
//!
//! One watch channel tells the accept loops to stop accepting and the open
//! connections to ask their clients to leave. It turns `true` once and never
//! back. How long the connections then get to finish is up to whoever
//! waits for them
//! ([`Listeners::serve_until_drained`](crate::Listeners::serve_until_drained)).
//! What draining means to a protocol (a `GOAWAY`, the end of keep-alive)
//! is up to the code that serves the connection.

use tokio::sync::watch;

/// A process's drain signal: `false` while serving, `true` once draining.
#[derive(Debug)]
pub struct Drain {
    tx: watch::Sender<bool>,
}

impl Drain {
    /// A signal that has not been given.
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(false);
        Drain { tx }
    }

    /// A receiver that sees the signal, whether it is given before or after
    /// this call.
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.tx.subscribe()
    }

    /// Begin draining: every subscriber sees `true`. Calling it again
    /// changes nothing.
    pub fn trigger(&self) {
        self.tx
            .send_if_modified(|draining| !std::mem::replace(draining, true));
    }

    /// Whether [`trigger`](Drain::trigger) has been called.
    pub fn is_draining(&self) -> bool {
        *self.tx.borrow()
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
