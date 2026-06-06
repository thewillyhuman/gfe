//! The agent ↔ controller wire protocol (spec §7). The agent long-polls
//! `GetTarget`; when a newer revision exists the controller returns the
//! rendered bytes plus the cert blobs to materialize. The agent applies and
//! calls `ReportStatus`.

use crate::node::ReloadState;
use serde::{Deserialize, Serialize};

/// Agent → controller: "what should node `node_id` in `fleet` be running?".
/// `current_seq` is the revision the agent has applied (for long-poll: the
/// controller returns once a *newer* allowed target exists).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetTargetRequest {
    pub fleet: String,
    pub node_id: String,
    #[serde(default)]
    pub current_seq: Option<i64>,
}

/// Controller → agent. Either the node is already at its allowed target, or a
/// new target is shipped with the bytes needed to apply it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GetTargetResponse {
    /// The node is at (or ahead of) the revision it is currently allowed to run.
    UpToDate,
    /// A new revision the node should converge to.
    Target(Box<TargetRevision>),
}

/// The shipped revision: rendered files + cert blobs to materialize first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetRevision {
    pub seq: i64,
    pub content_hash: String,
    /// Rendered `DynamicConfig` JSON (written atomically to `config_file`).
    pub dynamic_json: String,
    /// Rendered bootstrap TOML for this specific node (identity injected).
    pub static_toml: String,
    /// Cert material to write to content-addressed paths before the JSON swap.
    pub certs: Vec<TargetCert>,
    /// `true` when only the static (cold) config changed — the agent writes the
    /// TOML and signals "restart required" rather than hot-swapping (spec §8.3).
    #[serde(default)]
    pub static_only: bool,
}

/// One certificate's on-node paths and PEM material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetCert {
    pub path: String,
    pub key_path: String,
    pub content_sha: String,
    pub cert_pem: String,
    pub key_pem: String,
}

/// Agent → controller: the result of applying a target (spec §7 step 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportStatusRequest {
    pub fleet: String,
    pub node_id: String,
    pub applied_seq: i64,
    pub reload_state: ReloadState,
    pub healthy: bool,
}

/// Controller → agent acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportStatusResponse {
    pub ok: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn up_to_date_tag() {
        let json = serde_json::to_string(&GetTargetResponse::UpToDate).unwrap();
        assert_eq!(json, r#"{"status":"up_to_date"}"#);
    }

    #[test]
    fn target_round_trips() {
        let t = GetTargetResponse::Target(Box::new(TargetRevision {
            seq: 3,
            content_hash: "abc".into(),
            dynamic_json: "{}".into(),
            static_toml: "[node]\n".into(),
            certs: vec![],
            static_only: false,
        }));
        let json = serde_json::to_string(&t).unwrap();
        let back: GetTargetResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn report_status_round_trips() {
        let r = ReportStatusRequest {
            fleet: "atlas-prod".into(),
            node_id: "gfe-node-01".into(),
            applied_seq: 5,
            reload_state: ReloadState::Ok,
            healthy: true,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: ReportStatusRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}
