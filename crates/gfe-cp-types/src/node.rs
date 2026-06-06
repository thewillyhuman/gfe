//! A node: one frontend replica within a fleet (spec §3.2). Carries both
//! desired identity (set by operators) and observed state (written back by the
//! agent via `ReportStatus`).

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Per-node desired identity plus the last state the agent reported.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Node {
    /// Owning fleet name.
    pub fleet: String,
    /// → TOML `[node] id`; unique within the fleet.
    pub gfe_node_id: String,
    /// Agent reachability / inventory address.
    pub mgmt_addr: IpAddr,
    /// → TOML `[node] metrics_addr` (default `127.0.0.1:9101`).
    #[serde(default = "default_metrics_addr")]
    pub metrics_addr: String,
    /// → TOML `[node] worker_threads`. `0` = Tokio default.
    #[serde(default)]
    pub worker_threads: usize,
    /// Disabled nodes are excluded from rollout accounting.
    #[serde(default = "default_true")]
    pub enabled: bool,

    // ── observed state (written by the agent) ──
    /// Revision sequence the agent reports as currently applied.
    #[serde(default)]
    pub applied_seq: Option<i64>,
    /// Unix seconds of the last `ReportStatus` from this node.
    #[serde(default)]
    pub last_seen: i64,
    /// Result of the node's most recent reload.
    #[serde(default)]
    pub reload_state: ReloadState,
    /// Whether the node's data plane reports itself healthy (`/readyz`).
    #[serde(default)]
    pub healthy: bool,
}

fn default_metrics_addr() -> String {
    "127.0.0.1:9101".to_string()
}

fn default_true() -> bool {
    true
}

impl Node {
    /// A node that has not yet reported any applied state.
    pub fn new(
        fleet: impl Into<String>,
        gfe_node_id: impl Into<String>,
        mgmt_addr: IpAddr,
    ) -> Self {
        Node {
            fleet: fleet.into(),
            gfe_node_id: gfe_node_id.into(),
            mgmt_addr,
            metrics_addr: default_metrics_addr(),
            worker_threads: 0,
            enabled: true,
            applied_seq: None,
            last_seen: 0,
            reload_state: ReloadState::Pending,
            healthy: false,
        }
    }
}

/// Outcome of the node's most recent attempt to apply a revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ReloadState {
    /// Not yet applied (newly registered or awaiting first target).
    #[default]
    Pending,
    /// The node validated and swapped in the revision.
    Ok,
    /// The node rejected the revision and kept its previous snapshot.
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_defaults() {
        let n = Node::new("atlas-prod", "gfe-node-01", "10.0.0.1".parse().unwrap());
        assert_eq!(n.metrics_addr, "127.0.0.1:9101");
        assert!(n.enabled);
        assert_eq!(n.reload_state, ReloadState::Pending);
        assert!(n.applied_seq.is_none());
    }

    #[test]
    fn reload_state_serializes_uppercase() {
        assert_eq!(serde_json::to_string(&ReloadState::Ok).unwrap(), "\"OK\"");
    }
}
