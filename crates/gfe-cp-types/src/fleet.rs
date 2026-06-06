//! A fleet: a set of interchangeable nodes sharing one dynamic config and one
//! policy block (spec §3.1). The fleet's policy fields feed the per-node
//! bootstrap TOML; its resources (listeners, certs, pools, routes) feed the
//! shared dynamic JSON.

use gfe_types::duration::{deserialize_duration, serialize_duration};
use gfe_types::{HealthCheckConfig, MinVersion};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

/// Fleet-wide desired state and policy. The `name` is the stable key operators
/// use; `vip` is the service VIP held on each node's loopback (DSR).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fleet {
    pub name: String,
    pub vip: IpAddr,
    /// → TOML `[tls] min_version`.
    #[serde(default)]
    pub tls_min_version: MinVersion,
    /// → TOML `[tls] hsts`. Empty disables HSTS injection.
    #[serde(default)]
    pub hsts: String,
    /// Reference to a secret holding fleet-shared TLS ticket keys, if any.
    #[serde(default)]
    pub ticket_key_ref: Option<String>,
    /// → TOML `[limits]`.
    #[serde(default)]
    pub limits: LimitsSpec,
    /// → TOML `[timeouts]`.
    #[serde(default)]
    pub timeouts: TimeoutsSpec,
    /// → TOML `[upstream]`.
    #[serde(default)]
    pub upstream: UpstreamSpec,
    /// → TOML `[health_check_defaults]` and the dynamic-config pool fallback.
    #[serde(default)]
    pub health_defaults: HealthCheckConfig,
    /// How a published revision is rolled out across the fleet (spec §8).
    #[serde(default)]
    pub rollout_policy: RolloutPolicy,
    /// Unix seconds; stamped by the store.
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub updated_at: i64,
}

impl Fleet {
    /// A new fleet with policy defaults; only identity is required up front.
    pub fn new(name: impl Into<String>, vip: IpAddr) -> Self {
        Fleet {
            name: name.into(),
            vip,
            tls_min_version: MinVersion::default(),
            hsts: String::new(),
            ticket_key_ref: None,
            limits: LimitsSpec::default(),
            timeouts: TimeoutsSpec::default(),
            upstream: UpstreamSpec::default(),
            health_defaults: HealthCheckConfig::default(),
            rollout_policy: RolloutPolicy::default(),
            created_at: 0,
            updated_at: 0,
        }
    }
}

/// Mirrors `gfe_types::LimitsConfig` but is serializable (the node type is
/// deserialize-only). Defaults match the node's defaults so an unset field
/// renders the same value the node would have chosen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitsSpec {
    pub max_connections: usize,
    pub max_connections_listener: usize,
    pub max_header_bytes: usize,
    pub max_h2_concurrent_streams: u32,
    pub max_upstream_connections: usize,
}

impl Default for LimitsSpec {
    fn default() -> Self {
        LimitsSpec {
            max_connections: 100_000,
            max_connections_listener: 50_000,
            max_header_bytes: 65_536,
            max_h2_concurrent_streams: 256,
            max_upstream_connections: 20_000,
        }
    }
}

/// Mirrors `gfe_types::TimeoutsConfig`; serializable with the same friendly
/// duration format the node parses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutsSpec {
    #[serde(with = "dur")]
    pub tls_handshake: Duration,
    #[serde(with = "dur")]
    pub request_header: Duration,
    #[serde(with = "dur")]
    pub upstream_connect: Duration,
    #[serde(with = "dur")]
    pub upstream_first_byte: Duration,
    #[serde(with = "dur")]
    pub request_total: Duration,
    #[serde(with = "dur")]
    pub client_idle: Duration,
    #[serde(with = "dur")]
    pub drain_deadline: Duration,
}

impl Default for TimeoutsSpec {
    fn default() -> Self {
        TimeoutsSpec {
            tls_handshake: Duration::from_secs(10),
            request_header: Duration::from_secs(10),
            upstream_connect: Duration::from_secs(3),
            upstream_first_byte: Duration::from_secs(30),
            request_total: Duration::from_secs(60),
            client_idle: Duration::from_secs(75),
            drain_deadline: Duration::from_secs(30),
        }
    }
}

/// Mirrors `gfe_types::UpstreamConfig` (the upstream-leg settings). Cert/CA
/// fields are references to stored secrets resolved at render time, not paths.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamSpec {
    #[serde(default)]
    pub idle_per_host: Option<usize>,
    #[serde(default)]
    pub client_cert_ref: Option<String>,
    #[serde(default)]
    pub extra_ca_ref: Option<String>,
}

/// Rollout policy (spec §8.2). `canary_size` nodes go first, then traffic is
/// advanced in `wave_pct` increments, each gated on a `bake_time` health hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutPolicy {
    /// Nodes advanced in the first (canary) step.
    pub canary_size: u32,
    /// Percent of the fleet advanced per wave after the canary (1..=100).
    pub wave_pct: u32,
    /// Hold time before a step is considered healthy and the next may start.
    #[serde(with = "dur")]
    pub bake_time: Duration,
}

impl Default for RolloutPolicy {
    fn default() -> Self {
        RolloutPolicy {
            canary_size: 1,
            wave_pct: 100,
            bake_time: Duration::from_secs(0),
        }
    }
}

impl RolloutPolicy {
    /// An "all at once" policy: every node may advance immediately. Used by the
    /// MVP publish path before staged rollout (Phase 2) is engaged.
    pub fn all_at_once() -> Self {
        RolloutPolicy {
            canary_size: u32::MAX,
            wave_pct: 100,
            bake_time: Duration::from_secs(0),
        }
    }
}

/// Serde adapter applying the node's human-readable duration format.
mod dur {
    use super::*;
    pub fn serialize<S: serde::Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        serialize_duration(d, s)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        deserialize_duration(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fleet_round_trips() {
        let f = Fleet::new("atlas-prod", "188.184.100.10".parse().unwrap());
        let json = serde_json::to_string(&f).unwrap();
        let back: Fleet = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn timeouts_use_friendly_durations() {
        let t = TimeoutsSpec::default();
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["upstream_connect"], "3s");
        assert_eq!(json["client_idle"], "75s");
    }

    #[test]
    fn all_at_once_admits_every_node() {
        let p = RolloutPolicy::all_at_once();
        assert_eq!(p.canary_size, u32::MAX);
        assert_eq!(p.bake_time, Duration::from_secs(0));
    }
}
