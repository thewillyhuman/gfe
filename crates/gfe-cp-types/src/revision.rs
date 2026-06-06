//! Immutable, content-addressed revisions (spec §3.7). A revision captures the
//! exact rendered output for a fleet at a point in time; publishing one makes
//! it the rollout target, and rollback selects an earlier `seq`.

use serde::{Deserialize, Serialize};

/// One rendered, immutable configuration snapshot for a fleet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revision {
    pub fleet: String,
    /// Monotonic per-fleet sequence.
    pub seq: i64,
    /// The exact rendered `DynamicConfig` JSON (text).
    pub dynamic_json: String,
    /// Cert paths + hashes this revision references.
    pub cert_set: Vec<CertRef>,
    /// Fleet portion of the bootstrap TOML; the per-node `[node]` section is
    /// injected when the revision is served to a specific node.
    pub static_template: String,
    /// Hash over the rendered output; the stable rollout-target id.
    pub content_hash: String,
    pub created_by: String,
    pub created_at: i64,
}

/// A cert referenced by a revision: its on-node path and content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertRef {
    pub path: String,
    pub key_path: String,
    pub content_sha: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revision_round_trips() {
        let r = Revision {
            fleet: "atlas-prod".into(),
            seq: 1,
            dynamic_json: "{}".into(),
            cert_set: vec![CertRef {
                path: "/etc/gfe/certs/a.crt.pem".into(),
                key_path: "/etc/gfe/certs/a.key.pem".into(),
                content_sha: "a".into(),
            }],
            static_template: "[tls]\n".into(),
            content_hash: "deadbeef".into(),
            created_by: "alice".into(),
            created_at: 0,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: Revision = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}
