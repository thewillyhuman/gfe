//! Fleet-scoped resources that feed the dynamic config: listeners,
//! certificates, pools + backends, and routes (spec §3.3–§3.6). Each maps onto
//! a `gfe-types` struct during render.

use gfe_types::{HealthCheckConfig, LbPolicy, ListenProtocol, Scheme};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// A bound address + port (spec §3.3). `name` becomes the listener id routes
/// reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerSpec {
    pub name: String,
    pub address: IpAddr,
    pub port: u16,
    pub protocol: ListenProtocol,
}

/// A certificate stored in the control plane (spec §3.4). PEM material is held
/// by the store (encrypted at rest); this struct carries the metadata and the
/// content hash that drives the on-node, content-addressed path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    /// Stable id (the content hash). Set by the store on insert.
    pub content_sha: String,
    /// SNI names served (exact or single-label wildcard). Empty when default.
    #[serde(default)]
    pub sni: Vec<String>,
    /// At most one default per fleet (enforced by the store).
    #[serde(default)]
    pub is_default: bool,
    /// Leaf-certificate expiry (unix seconds) for expiry alerting / refusal.
    #[serde(default)]
    pub not_after: i64,
    #[serde(default)]
    pub created_at: i64,
}

impl Certificate {
    /// On-node certificate path: `/etc/gfe/certs/<sha>.crt.pem`.
    pub fn cert_path(&self) -> String {
        format!("/etc/gfe/certs/{}.crt.pem", self.content_sha)
    }
    /// On-node private-key path: `/etc/gfe/certs/<sha>.key.pem`.
    pub fn key_path(&self) -> String {
        format!("/etc/gfe/certs/{}.key.pem", self.content_sha)
    }
}

/// A named set of backends (spec §3.5). `health_check` overrides the fleet
/// defaults when present.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PoolSpec {
    pub name: String,
    #[serde(default)]
    pub scheme: Scheme,
    #[serde(default)]
    pub lb_policy: LbPolicy,
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
    #[serde(default)]
    pub backends: Vec<Backend>,
}

/// A single application backend (spec §3.5). Disabled rows are omitted from the
/// render — the offboard path without deleting the row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backend {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_weight() -> u32 {
    1
}
fn default_true() -> bool {
    true
}

/// A routing rule (spec §3.6). `listener` and `forward_pool` are names resolved
/// at render time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteSpec {
    pub name: String,
    pub listener: String,
    pub host: String,
    #[serde(default = "default_path_prefix")]
    pub path_prefix: String,
    pub action: RouteActionSpec,
}

fn default_path_prefix() -> String {
    "/".to_string()
}

/// What a matching route does (spec §3.6). Mirrors `gfe_types::RouteAction`
/// but references the pool by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteActionSpec {
    /// Forward to the named pool.
    Forward(String),
    /// Respond with a redirect.
    Redirect(RedirectSpec),
    /// Respond with a fixed status + body, no upstream call.
    Fixed(FixedSpec),
}

/// A redirect action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedirectSpec {
    pub scheme: String,
    #[serde(default = "default_redirect_status")]
    pub status: u16,
}

fn default_redirect_status() -> u16 {
    308
}

/// A fixed-status action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedSpec {
    pub status: u16,
    #[serde(default)]
    pub body: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_paths_are_content_addressed() {
        let c = Certificate {
            content_sha: "abc123".into(),
            sni: vec!["a.example.org".into()],
            is_default: false,
            not_after: 0,
            created_at: 0,
        };
        assert_eq!(c.cert_path(), "/etc/gfe/certs/abc123.crt.pem");
        assert_eq!(c.key_path(), "/etc/gfe/certs/abc123.key.pem");
    }

    #[test]
    fn backend_defaults() {
        let b: Backend = serde_json::from_str(r#"{"host":"10.0.0.1","port":8443}"#).unwrap();
        assert_eq!(b.weight, 1);
        assert!(b.enabled);
    }

    #[test]
    fn route_action_forward_round_trips() {
        let r = RouteActionSpec::Forward("web".into());
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, r#"{"forward":"web"}"#);
        let back: RouteActionSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}
