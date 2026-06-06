//! Rollout gating (spec §8): decides which revision a given node is *allowed*
//! to advance to right now. The agent always pulls toward this allowed target,
//! so staging a rollout is purely a matter of which sequence this returns.
//!
//! MVP behaviour is "all at once": every node is allowed to advance straight to
//! the fleet's published target. Phase 2 replaces the body of
//! [`allowed_target`] with canary/wave gating and auto-halt while keeping this
//! exact signature, so the server's agent path does not change.

use crate::store::{Store, StoreError};

/// The revision sequence node `node_id` in `fleet` may currently apply, or
/// `None` if nothing has been published yet.
pub fn allowed_target(
    store: &Store,
    fleet: &str,
    _node_id: &str,
) -> Result<Option<i64>, StoreError> {
    store.target_seq(fleet)
}
