//! Upstream pools: the backends a route forwards to, and how one is chosen.

use crate::HealthCheckConfig;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;

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
    /// Cleartext HTTP/1.1.
    #[default]
    Http,
    /// TLS; HTTP/1.1, or HTTP/2 as negotiated by ALPN for requests that
    /// need it (gRPC).
    Https,
    /// Cleartext HTTP/2 with prior knowledge, for backends that speak only
    /// HTTP/2 without TLS (typically gRPC servers).
    H2c,
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
    /// A hostname or an IP literal; an IPv6 address without brackets.
    pub host: String,
    pub port: u16,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    1
}

impl Upstream {
    /// `host:port` authority string: where the node connects, the key of the
    /// connection pool, and the `:authority` of the HTTP/2 requests it sends
    /// there (an HTTP/1 request carries the client's `Host` instead). An IPv6
    /// literal, written without brackets in the config, is bracketed
    /// (`[2001:db8::1]:443`) as a URI authority requires.
    pub fn authority(&self) -> String {
        if self.host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
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
    /// The most requests the node may have in flight to the pool at once,
    /// so that a slow pool cannot take every upstream connection the node
    /// may open. A request beyond it is answered `503`. Absent: no quota.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_in_flight: Option<NonZeroU32>,
}

#[cfg(test)]
#[path = "pool_test.rs"]
mod tests;
