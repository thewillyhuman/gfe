use crate::duration::{deserialize_duration, serialize_duration};
use crate::listener::Listener;
use crate::route::Route;
use crate::tls::{CertEntry, TlsConfig};
use crate::upstream::UpstreamPool;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

// ───────────────────────── Bootstrap node config (TOML) ─────────────────────────

/// Top-level node configuration, read once at startup from a TOML file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub node: NodeSection,
    pub control_plane: ControlPlaneConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub timeouts: TimeoutsConfig,
    #[serde(default)]
    pub upstream: UpstreamConfig,
    pub health_check_defaults: HealthCheckConfig,
}

/// Upstream-leg (GFE → backend) connection settings.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    /// Idle pooled connections kept per backend authority. `None` → 32.
    #[serde(default)]
    pub idle_per_host: Option<usize>,
    /// Client certificate (PEM) presented to upstreams for mTLS.
    #[serde(default)]
    pub client_cert_file: Option<PathBuf>,
    /// Client private key (PEM) for mTLS. Required if `client_cert_file` is set.
    #[serde(default)]
    pub client_key_file: Option<PathBuf>,
    /// Additional CA bundle (PEM) trusted for upstream TLS, on top of the
    /// system/webpki roots.
    #[serde(default)]
    pub extra_ca_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSection {
    pub id: String,
    /// The service VIP configured on this node's loopback (DSR). Informational
    /// for logging/metrics; listeners bind the address in the dynamic config.
    pub loopback_vip: IpAddr,
    /// Address for the operations HTTP server (`/healthz`, `/readyz`,
    /// `/metrics`). Defaults to `127.0.0.1:9101`.
    #[serde(default = "default_metrics_addr")]
    pub metrics_addr: SocketAddr,
    /// Tokio worker thread count. `0` (the default) means the Tokio default
    /// (= number of CPUs).
    #[serde(default)]
    pub worker_threads: usize,
}

fn default_metrics_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 9101))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneConfig {
    /// Path to the dynamic config (listeners/routes/pools/certs), watched via
    /// inotify and hot-reloaded.
    pub config_file: PathBuf,
    /// Last-known-good cache written on every successful reload.
    #[serde(default)]
    pub local_cache: Option<PathBuf>,
    /// Coalesce rapid successive file writes into one reload.
    #[serde(
        default = "default_reload_debounce",
        deserialize_with = "deserialize_duration"
    )]
    pub reload_debounce: Duration,
}

fn default_reload_debounce() -> Duration {
    Duration::from_millis(250)
}

/// Connection/header/stream limits that bound resource use under load.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_max_connections_listener")]
    pub max_connections_listener: usize,
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: usize,
    #[serde(default = "default_max_h2_streams")]
    pub max_h2_concurrent_streams: u32,
    #[serde(default = "default_max_upstream_connections")]
    pub max_upstream_connections: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            max_connections: default_max_connections(),
            max_connections_listener: default_max_connections_listener(),
            max_header_bytes: default_max_header_bytes(),
            max_h2_concurrent_streams: default_max_h2_streams(),
            max_upstream_connections: default_max_upstream_connections(),
        }
    }
}

fn default_max_connections() -> usize {
    100_000
}
fn default_max_connections_listener() -> usize {
    50_000
}
fn default_max_header_bytes() -> usize {
    65_536
}
fn default_max_h2_streams() -> u32 {
    256
}
fn default_max_upstream_connections() -> usize {
    20_000
}

/// Timeouts applied across the connection and request lifecycle.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeoutsConfig {
    #[serde(default = "d10s", deserialize_with = "deserialize_duration")]
    pub tls_handshake: Duration,
    #[serde(default = "d10s", deserialize_with = "deserialize_duration")]
    pub request_header: Duration,
    #[serde(default = "d3s", deserialize_with = "deserialize_duration")]
    pub upstream_connect: Duration,
    #[serde(default = "d30s", deserialize_with = "deserialize_duration")]
    pub upstream_first_byte: Duration,
    #[serde(default = "d60s", deserialize_with = "deserialize_duration")]
    pub request_total: Duration,
    #[serde(default = "d75s", deserialize_with = "deserialize_duration")]
    pub client_idle: Duration,
    #[serde(default = "d30s", deserialize_with = "deserialize_duration")]
    pub drain_deadline: Duration,
}

impl Default for TimeoutsConfig {
    fn default() -> Self {
        TimeoutsConfig {
            tls_handshake: d10s(),
            request_header: d10s(),
            upstream_connect: d3s(),
            upstream_first_byte: d30s(),
            request_total: d60s(),
            client_idle: d75s(),
            drain_deadline: d30s(),
        }
    }
}

fn d3s() -> Duration {
    Duration::from_secs(3)
}
fn d10s() -> Duration {
    Duration::from_secs(10)
}
fn d30s() -> Duration {
    Duration::from_secs(30)
}
fn d60s() -> Duration {
    Duration::from_secs(60)
}
fn d75s() -> Duration {
    Duration::from_secs(75)
}

/// Health-check parameters; used both as node defaults and (optionally)
/// per-pool overrides in the dynamic config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    /// Probe type: `http`, `https`, or `tcp`.
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
    #[default]
    Http,
    Https,
    Tcp,
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

// ───────────────────────── Dynamic config (JSON) ─────────────────────────

/// The hot-reloadable configuration: certificates, listeners, routes, pools.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicConfig {
    #[serde(default)]
    pub certificates: Vec<CertEntry>,
    #[serde(default)]
    pub listeners: Vec<Listener>,
    #[serde(default)]
    pub routes: Vec<Route>,
    #[serde(default)]
    pub pools: Vec<UpstreamPool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_config_minimal_toml() {
        let toml_str = r#"
[node]
id = "gfe-node-01"
loopback_vip = "188.184.100.10"

[control_plane]
config_file = "/etc/gfe/gfe-dynamic.json"

[health_check_defaults]
"#;
        let cfg: NodeConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.node.id, "gfe-node-01");
        assert_eq!(cfg.node.metrics_addr.port(), 9101);
        assert_eq!(
            cfg.control_plane.reload_debounce,
            Duration::from_millis(250)
        );
        assert_eq!(cfg.limits.max_connections, 100_000);
        assert_eq!(cfg.timeouts.upstream_connect, Duration::from_secs(3));
        assert_eq!(cfg.health_check_defaults.interval, Duration::from_secs(5));
    }

    #[test]
    fn dynamic_config_json() {
        let json = r#"{
            "certificates": [{"default": true, "cert_file": "/c.pem", "key_file": "/k.pem"}],
            "listeners": [{"id":"https","address":"0.0.0.0","port":443,"protocol":"https"}],
            "routes": [{"id":"r","listener":"https","host":"a.example.org","action":{"forward":"p"}}],
            "pools": [{"id":"p","scheme":"https","upstreams":[{"host":"10.0.0.1","port":8443}]}]
        }"#;
        let cfg: DynamicConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.certificates.len(), 1);
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(cfg.routes.len(), 1);
        assert_eq!(cfg.pools.len(), 1);
    }
}
