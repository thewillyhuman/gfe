//! The bootstrap config: what a node is, read once when it starts (TOML).

use crate::duration::deserialize_duration;
use crate::{HealthCheckConfig, TlsConfig};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::time::Duration;

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
    /// Deprecated and ignored: every node attempts to attach the kernel
    /// view. Still accepted so that existing files load; `Some` when the
    /// file has the section, so that [`NodeConfig::deprecations`] can say so.
    #[serde(default)]
    pub ebpf: Option<EbpfConfig>,
    #[serde(default)]
    pub log: LogConfig,
    pub health_check_defaults: HealthCheckConfig,
}

impl NodeConfig {
    /// One sentence per deprecated key this config sets, saying what to do
    /// about it, for the node to log as a warning when it starts. Empty when
    /// the file sets none.
    pub fn deprecations(&self) -> Vec<String> {
        let mut deprecations = Vec::new();
        if self.node.loopback_vip.is_some() {
            deprecations.push(
                "[node] loopback_vip is deprecated and ignored: listeners bind the \
                 addresses of the dynamic config; remove it"
                    .to_string(),
            );
        }
        if self.ebpf.is_some() {
            deprecations.push(
                "[ebpf] is deprecated and ignored: every node attempts to attach the \
                 kernel view; remove the section"
                    .to_string(),
            );
        }
        deprecations
    }
}

/// Where the node's log goes.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// A file to append every log line to. The node then keeps the events
    /// that describe traffic (one per request and per connection) off
    /// standard output, which carries its own log only. Without a file,
    /// everything goes to standard output.
    ///
    /// The file may be rotated under the node, by renaming or truncating it:
    /// the node goes on at this path within a second.
    #[serde(default)]
    pub file: Option<PathBuf>,
}

/// The `[ebpf]` section. Deprecated and ignored: the kernel view of the
/// node's TCP connections is no longer optional, and every node attempts to
/// attach it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EbpfConfig {
    /// Ignored, whatever its value.
    #[serde(default)]
    pub enabled: bool,
}

/// Upstream-leg (GFE → backend) connection settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    /// The most idle pooled connections kept per backend. `None` or 0
    /// keeps every idle connection, bounded by `idle_timeout` and
    /// `max_upstream_connections` alone.
    #[serde(default)]
    pub idle_per_host: Option<usize>,
    /// How long a pooled connection may stay idle before it is closed.
    /// Bounds how long connections to a backend that is no longer used
    /// (removed, or dead) stay open and count against
    /// `max_upstream_connections`.
    #[serde(default = "d60s", deserialize_with = "deserialize_duration")]
    pub idle_timeout: Duration,
    /// Client certificate (PEM) presented to upstreams for mTLS.
    #[serde(default)]
    pub client_cert_file: Option<PathBuf>,
    /// Client private key (PEM) for mTLS. Required if `client_cert_file` is set.
    #[serde(default)]
    pub client_key_file: Option<PathBuf>,
    /// Additional CA bundle (PEM) trusted for upstream TLS, on top of the
    /// system's trust store.
    #[serde(default)]
    pub extra_ca_file: Option<PathBuf>,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        UpstreamConfig {
            idle_per_host: None,
            idle_timeout: d60s(),
            client_cert_file: None,
            client_key_file: None,
            extra_ca_file: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSection {
    pub id: String,
    /// Deprecated and ignored: nothing assumes how traffic reaches the node,
    /// and listeners bind the addresses of the dynamic config. Still
    /// accepted so that existing files load.
    #[serde(default)]
    pub loopback_vip: Option<IpAddr>,
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
    /// The most new connections one client address may open per second,
    /// over every listener; a client that has been quiet may open a
    /// second's worth at once. A connection over it is closed as soon as
    /// it is accepted. Absent: no cap.
    #[serde(default)]
    pub client_connections_per_second: Option<NonZeroU32>,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            max_connections: default_max_connections(),
            max_connections_listener: default_max_connections_listener(),
            max_header_bytes: default_max_header_bytes(),
            max_h2_concurrent_streams: default_max_h2_streams(),
            max_upstream_connections: default_max_upstream_connections(),
            client_connections_per_second: None,
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

#[cfg(test)]
#[path = "node_test.rs"]
mod tests;
