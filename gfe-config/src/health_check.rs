//! How a backend is probed to decide whether it gets traffic.

use crate::duration::{deserialize_duration, serialize_duration};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Health-check parameters; used both as node defaults and (optionally)
/// per-pool overrides in the dynamic config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    /// Probe type: `http`, `https`, `tcp`, or `grpc`.
    #[serde(default = "default_probe_type", rename = "type")]
    pub probe_type: ProbeType,
    #[serde(
        default = "d5s",
        deserialize_with = "deserialize_duration",
        serialize_with = "serialize_duration"
    )]
    pub interval: Duration,
    #[serde(
        default = "d2s",
        deserialize_with = "deserialize_duration",
        serialize_with = "serialize_duration"
    )]
    pub timeout: Duration,
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
    /// Request path for http/https probes.
    #[serde(default = "default_health_path")]
    pub path: String,
    /// Expected status code for http/https probes.
    #[serde(default = "default_expected_status")]
    pub expected_status: u16,
    /// Optional lame-duck signal: when an http/https probe returns this status,
    /// the backend is moved to `DRAINING` (excluded from new requests while
    /// in-flight requests complete) rather than `UNHEALTHY`.
    #[serde(default)]
    pub drain_status: Option<u16>,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        HealthCheckConfig {
            probe_type: default_probe_type(),
            interval: d5s(),
            timeout: d2s(),
            healthy_threshold: default_healthy_threshold(),
            unhealthy_threshold: default_unhealthy_threshold(),
            path: default_health_path(),
            expected_status: default_expected_status(),
            drain_status: None,
        }
    }
}

/// Health-check probe type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeType {
    /// `GET` the configured path over HTTP/1.1: over TLS for `https` pools
    /// and cleartext otherwise, the way the pool's traffic reaches it.
    #[default]
    Http,
    /// The same, always over TLS, whatever the pool's scheme.
    Https,
    /// A TCP connection can be established.
    Tcp,
    /// The gRPC health-checking protocol (`grpc.health.v1.Health/Check`),
    /// over TLS for `https` pools and cleartext HTTP/2 otherwise.
    Grpc,
}

fn default_probe_type() -> ProbeType {
    ProbeType::Http
}
fn d2s() -> Duration {
    Duration::from_secs(2)
}
fn d5s() -> Duration {
    Duration::from_secs(5)
}
fn default_healthy_threshold() -> u32 {
    2
}
fn default_unhealthy_threshold() -> u32 {
    3
}
fn default_health_path() -> String {
    "/healthz".to_string()
}
fn default_expected_status() -> u16 {
    200
}

#[cfg(test)]
#[path = "health_check_test.rs"]
mod tests;
