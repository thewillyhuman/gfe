//! Audit trail entries (spec §10): a record of every desired-state change and
//! every published/rolled-back revision — who, what, when.

use serde::{Deserialize, Serialize};

/// One audited action against a fleet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unix seconds.
    pub ts: i64,
    /// Who performed the action (from the request actor, or "operator").
    pub actor: String,
    /// What was done, e.g. `POST /v1/fleets/atlas-prod/publish`.
    pub action: String,
    /// Optional extra detail (e.g. resulting revision sequence).
    #[serde(default)]
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let e = AuditEntry {
            ts: 100,
            actor: "alice".into(),
            action: "POST /v1/fleets/f/publish".into(),
            detail: "seq=3".into(),
        };
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(serde_json::from_str::<AuditEntry>(&json).unwrap(), e);
    }
}
