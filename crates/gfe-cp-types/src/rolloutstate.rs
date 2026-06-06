//! Observed rollout progress for a fleet's current target (spec §8.2). Created
//! when a target is published and advanced as nodes report success. Drives the
//! gating decision (which nodes may advance) and is surfaced in `fleet status`.

use serde::{Deserialize, Serialize};

/// Where a fleet's rollout currently stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutState {
    /// The revision being rolled out.
    pub target_seq: i64,
    /// Number of leading nodes (sorted by id) admitted to the target so far.
    /// Grows from the canary size by waves as earlier nodes clear.
    pub admitted: u32,
    /// Coarse phase for display + control.
    pub phase: RolloutPhase,
    /// Why the rollout halted, if it did.
    #[serde(default)]
    pub halted_reason: Option<String>,
    /// Unix seconds of the last admission advance (start of the bake window).
    pub last_advance_at: i64,
}

impl RolloutState {
    /// A fresh rollout admitting the first `canary` nodes at time `now`.
    pub fn new(target_seq: i64, canary: u32, now: i64) -> Self {
        RolloutState {
            target_seq,
            admitted: canary,
            phase: RolloutPhase::Canary,
            halted_reason: None,
            last_advance_at: now,
        }
    }
}

/// Coarse rollout phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutPhase {
    /// Only the canary set is admitted; awaiting it to clear + bake.
    Canary,
    /// Past the canary, advancing in waves.
    InProgress,
    /// Every node is at the target.
    Done,
    /// Advancing stopped after a node failed to reload or dropped health.
    Halted,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_in_canary() {
        let r = RolloutState::new(5, 1, 1000);
        assert_eq!(r.phase, RolloutPhase::Canary);
        assert_eq!(r.admitted, 1);
        assert_eq!(r.target_seq, 5);
    }

    #[test]
    fn phase_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&RolloutPhase::InProgress).unwrap(),
            "\"in_progress\""
        );
    }
}
