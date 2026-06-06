//! Rollout orchestration (spec §8.2): decides which revision a given node is
//! *allowed* to advance to right now, and reconciles fleet rollout progress as
//! nodes report success or failure.
//!
//! The model is deterministic over observed node state + the fleet's
//! `RolloutPolicy`. Nodes are ordered by id; the first `admitted` of them may
//! hold the target. Admission starts at the canary size and grows by waves once
//! the currently-admitted nodes have cleared (applied the target, reloaded OK,
//! and stayed healthy) and the bake window has elapsed. A node that fails to
//! reload or drops health halts advancement (auto-halt) — operators then roll
//! back or fix forward.
//!
//! The agent always pulls toward [`allowed_target`], so staging a rollout is
//! purely a function of what this returns; the agent code never changes.

use crate::store::{Store, StoreError};
use gfe_cp_types::{Node, ReloadState, RolloutPhase, RolloutState};

/// Whether a node has fully cleared the target (safe to advance past it).
fn cleared(n: &Node, target: i64) -> bool {
    n.applied_seq == Some(target) && n.reload_state == ReloadState::Ok && n.healthy
}

/// Whether a node tried the target and failed (drives auto-halt).
fn failed(n: &Node, target: i64) -> bool {
    n.applied_seq == Some(target) && (n.reload_state == ReloadState::Failed || !n.healthy)
}

/// Enabled nodes, ordered by id (the canary/wave ordering).
fn enabled_sorted(mut nodes: Vec<Node>) -> Vec<Node> {
    nodes.retain(|n| n.enabled);
    nodes.sort_by(|a, b| a.gfe_node_id.cmp(&b.gfe_node_id));
    nodes
}

/// Wave size: at least one node, otherwise `ceil(total * wave_pct / 100)`.
fn wave_size(total: u32, wave_pct: u32) -> u32 {
    let pct = wave_pct.clamp(1, 100);
    let n = (total as u64 * pct as u64).div_ceil(100) as u32;
    n.max(1)
}

/// Advance (or halt) a fleet's rollout given the latest observed node state and
/// the current time `now` (unix seconds). Returns the updated state, or `None`
/// if no rollout is in progress. Idempotent: terminal states are returned
/// unchanged.
pub fn reconcile(store: &Store, fleet: &str, now: i64) -> Result<Option<RolloutState>, StoreError> {
    let Some(mut state) = store.rollout(fleet)? else {
        return Ok(None);
    };
    if matches!(state.phase, RolloutPhase::Done | RolloutPhase::Halted) {
        return Ok(Some(state));
    }

    let policy = store.get_fleet(fleet)?.rollout_policy;
    let nodes = enabled_sorted(store.list_nodes(fleet)?);
    let total = nodes.len() as u32;
    let target = state.target_seq;
    let admitted = state.admitted.min(total);
    let admitted_nodes = &nodes[..admitted as usize];

    // Auto-halt: any admitted node that failed stops the rollout.
    if let Some(bad) = admitted_nodes.iter().find(|n| failed(n, target)) {
        state.phase = RolloutPhase::Halted;
        state.halted_reason = Some(format!(
            "node {} failed to apply revision {target}",
            bad.gfe_node_id
        ));
        store.set_rollout(fleet, state.clone())?;
        return Ok(Some(state));
    }

    // Advance once every admitted node has cleared and the bake window passed.
    if admitted_nodes.iter().all(|n| cleared(n, target)) {
        if admitted >= total {
            state.phase = RolloutPhase::Done;
        } else if now - state.last_advance_at >= policy.bake_time.as_secs() as i64 {
            let wave = wave_size(total, policy.wave_pct);
            state.admitted = (admitted + wave).min(total);
            state.last_advance_at = now;
            state.phase = RolloutPhase::InProgress;
        }
    }
    store.set_rollout(fleet, state.clone())?;
    Ok(Some(state))
}

/// The revision sequence node `node_id` in `fleet` may currently apply, or
/// `None` if nothing is published. Reconciles the rollout first, so an agent's
/// own poll is enough to drive progress forward.
pub fn allowed_target(
    store: &Store,
    fleet: &str,
    node_id: &str,
    now: i64,
) -> Result<Option<i64>, StoreError> {
    reconcile(store, fleet, now)?;
    let Some(state) = store.rollout(fleet)? else {
        return Ok(None);
    };
    let target = state.target_seq;
    let node = store.get_node(fleet, node_id)?;

    // A node already at the target keeps it (never rolled backward mid-rollout).
    if node.applied_seq == Some(target) {
        return Ok(Some(target));
    }

    let nodes = enabled_sorted(store.list_nodes(fleet)?);
    let admitted = state.admitted.min(nodes.len() as u32);
    let idx = nodes.iter().position(|n| n.gfe_node_id == node_id);
    let admitted_now =
        state.phase != RolloutPhase::Halted && matches!(idx, Some(i) if (i as u32) < admitted);
    if admitted_now {
        Ok(Some(target))
    } else {
        // Not yet admitted (or halted): keep serving the node's current config.
        Ok(node.applied_seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::AeadSealer;
    use gfe_cp_types::{Fleet, RolloutPolicy};
    use std::sync::Arc;
    use std::time::Duration;

    fn store_with(policy: RolloutPolicy, node_ids: &[&str]) -> Store {
        let s = Store::in_memory(Arc::new(AeadSealer::new(&[8u8; 32]).unwrap()));
        let mut fleet = Fleet::new("f", "10.0.0.1".parse().unwrap());
        fleet.rollout_policy = policy;
        s.create_fleet(fleet).unwrap();
        for id in node_ids {
            s.put_node(Node::new("f", *id, "10.0.0.9".parse().unwrap()))
                .unwrap();
        }
        // Two trivial revisions so we can target either.
        for h in ["h1", "h2"] {
            s.create_revision("f", "{}".into(), vec![], "".into(), h.into(), "t".into())
                .unwrap();
        }
        s
    }

    fn apply(s: &Store, node: &str, seq: i64, ok: bool) {
        let state = if ok {
            ReloadState::Ok
        } else {
            ReloadState::Failed
        };
        s.report_node_status("f", node, seq, state, ok).unwrap();
    }

    #[test]
    fn canary_then_full_wave() {
        // canary 1, then 100% wave, no bake.
        let policy = RolloutPolicy {
            canary_size: 1,
            wave_pct: 100,
            bake_time: Duration::ZERO,
        };
        let s = store_with(policy, &["n1", "n2", "n3"]);
        s.set_target("f", 1).unwrap();
        let t0 = s.rollout("f").unwrap().unwrap().last_advance_at;

        // Only the canary (n1) is admitted initially.
        assert_eq!(allowed_target(&s, "f", "n1", t0).unwrap(), Some(1));
        assert_eq!(allowed_target(&s, "f", "n2", t0).unwrap(), None);
        assert_eq!(allowed_target(&s, "f", "n3", t0).unwrap(), None);

        // Canary applies + clears → wave admits the rest.
        apply(&s, "n1", 1, true);
        assert_eq!(allowed_target(&s, "f", "n2", t0 + 1).unwrap(), Some(1));
        assert_eq!(allowed_target(&s, "f", "n3", t0 + 1).unwrap(), Some(1));

        apply(&s, "n2", 1, true);
        apply(&s, "n3", 1, true);
        reconcile(&s, "f", t0 + 2).unwrap();
        assert_eq!(s.rollout("f").unwrap().unwrap().phase, RolloutPhase::Done);
    }

    #[test]
    fn canary_failure_halts() {
        let policy = RolloutPolicy {
            canary_size: 1,
            wave_pct: 100,
            bake_time: Duration::ZERO,
        };
        let s = store_with(policy, &["n1", "n2", "n3"]);
        s.set_target("f", 1).unwrap();
        // Canary fails.
        apply(&s, "n1", 1, false);
        reconcile(&s, "f", 100).unwrap();
        let r = s.rollout("f").unwrap().unwrap();
        assert_eq!(r.phase, RolloutPhase::Halted);
        assert!(r.halted_reason.unwrap().contains("n1"));
        // Other nodes are NOT admitted while halted.
        assert_eq!(allowed_target(&s, "f", "n2", 200).unwrap(), None);
    }

    #[test]
    fn bake_time_gates_the_wave() {
        let policy = RolloutPolicy {
            canary_size: 1,
            wave_pct: 100,
            bake_time: Duration::from_secs(60),
        };
        let s = store_with(policy, &["n1", "n2"]);
        s.set_target("f", 1).unwrap();
        let started = s.rollout("f").unwrap().unwrap().last_advance_at;
        apply(&s, "n1", 1, true);
        // Within the bake window: wave not yet admitted.
        assert_eq!(allowed_target(&s, "f", "n2", started + 30).unwrap(), None);
        // After bake: admitted.
        assert_eq!(
            allowed_target(&s, "f", "n2", started + 61).unwrap(),
            Some(1)
        );
    }

    #[test]
    fn already_applied_node_keeps_target_even_if_unadmitted() {
        // A node that already has the target is never pulled back.
        let policy = RolloutPolicy {
            canary_size: 1,
            wave_pct: 100,
            bake_time: Duration::ZERO,
        };
        let s = store_with(policy, &["n1", "n2"]);
        s.set_target("f", 1).unwrap();
        apply(&s, "n2", 1, true); // n2 somehow already at target
        assert_eq!(allowed_target(&s, "f", "n2", 100).unwrap(), Some(1));
    }

    #[test]
    fn wave_size_rounds_up() {
        assert_eq!(wave_size(10, 25), 3);
        assert_eq!(wave_size(10, 100), 10);
        assert_eq!(wave_size(3, 1), 1);
        assert_eq!(wave_size(0, 50), 1);
    }
}
