use crate::config::HealthCheckConfig;
use serde::{Deserialize, Serialize};

/// Unique identifier for an upstream pool, referenced by routes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PoolId(pub String);

impl std::fmt::Display for PoolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The scheme GFE uses on the upstream leg (independent of the client-facing
/// listener protocol).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    #[default]
    Http,
    Https,
}

/// Load-balancing policy for distributing requests across healthy upstreams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LbPolicy {
    /// Even distribution across equal backends.
    #[default]
    RoundRobin,
    /// Prefer the backend with the fewest in-flight requests.
    LeastRequest,
    /// Consistent-hash on a key for session affinity.
    RingHash,
}

/// A single application backend within a pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    1
}

impl Upstream {
    /// `host:port` authority string, used as the connection-pool key and for
    /// the upstream request `Host` header.
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// A named set of backends serving the same role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamPool {
    pub id: PoolId,
    #[serde(default)]
    pub scheme: Scheme,
    #[serde(default)]
    pub lb_policy: LbPolicy,
    pub upstreams: Vec<Upstream>,
    /// Per-pool health check override. When absent, the node's
    /// `health_check_defaults` apply.
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
}

/// Health state of a single backend, tracked by the control plane and read by
/// the data plane on each upstream selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HealthStatus {
    /// Not yet probed enough times to decide.
    #[default]
    Unknown,
    /// Receiving traffic.
    Healthy,
    /// Failing checks; excluded from selection.
    Unhealthy,
    /// Lame-duck: excluded from *new* requests, existing ones drain.
    Draining,
}

impl HealthStatus {
    /// Whether a backend in this state may receive new requests.
    pub fn is_selectable(&self) -> bool {
        matches!(self, HealthStatus::Healthy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_serde_defaults() {
        let json = r#"{"id":"p","upstreams":[{"host":"10.0.0.1","port":8443}]}"#;
        let p: UpstreamPool = serde_json::from_str(json).unwrap();
        assert_eq!(p.scheme, Scheme::Http);
        assert_eq!(p.lb_policy, LbPolicy::RoundRobin);
        assert_eq!(p.upstreams[0].weight, 1);
        assert_eq!(p.upstreams[0].authority(), "10.0.0.1:8443");
    }

    #[test]
    fn health_selectable() {
        assert!(HealthStatus::Healthy.is_selectable());
        assert!(!HealthStatus::Draining.is_selectable());
        assert!(!HealthStatus::Unhealthy.is_selectable());
        assert!(!HealthStatus::Unknown.is_selectable());
    }
}
