//! The health checks of the dynamic config, as the health-checking library
//! takes them, and what it reports turned into the node's metrics.
//!
//! The library knows checks and probes, not schemes: whether a probe
//! speaks TLS is decided here, from the pool's scheme.

use gfe_config::{HealthCheckConfig, ProbeType, Scheme, UpstreamPool};
use netkit_health_checking::{CheckSpec, CheckedPool, HealthObserver, HealthStatus, ProbeKind};
use netkit_observability::{BackendLabels, GfeMetrics};
use std::sync::Arc;
use std::time::Duration;

/// The pools of the dynamic config with the check of each: its own, or the
/// node's `defaults` when it has none.
pub(crate) fn checked_pools(
    pools: &[UpstreamPool],
    defaults: &HealthCheckConfig,
) -> Vec<CheckedPool> {
    pools
        .iter()
        .map(|pool| {
            let check = pool.health_check.as_ref().unwrap_or(defaults);
            CheckedPool {
                id: pool.id.0.clone(),
                check: CheckSpec {
                    probe: probe_kind(check, pool.scheme),
                    interval: check.interval,
                    timeout: check.timeout,
                    healthy_threshold: check.healthy_threshold,
                    unhealthy_threshold: check.unhealthy_threshold,
                },
                backends: pool
                    .upstreams
                    .iter()
                    .map(|upstream| (upstream.host.clone(), upstream.port))
                    .collect(),
            }
        })
        .collect()
}

/// What a probe of `check` does for a backend of a pool of `scheme`.
fn probe_kind(check: &HealthCheckConfig, scheme: Scheme) -> ProbeKind {
    let http = |tls| ProbeKind::Http {
        path: check.path.clone(),
        expected_status: check.expected_status,
        drain_status: check.drain_status,
        tls,
    };
    match check.probe_type {
        ProbeType::Tcp => ProbeKind::Tcp,
        // A gRPC server is reached the way the pool's traffic reaches it.
        ProbeType::Grpc => ProbeKind::Grpc {
            tls: scheme == Scheme::Https,
        },
        // `http` is the node default, so it is what an `https` pool without
        // its own check gets: probing its TLS port in cleartext would fail
        // every backend.
        ProbeType::Http => http(scheme == Scheme::Https),
        ProbeType::Https => http(true),
    }
}

/// Feeds the backend health metrics (`gfe_backend_health_status`,
/// `gfe_backend_draining`, `gfe_health_check_duration_seconds`) from what
/// the health checker reports.
pub(crate) struct HealthMetrics(Arc<GfeMetrics>);

impl HealthMetrics {
    /// An observer recording into `metrics`.
    pub(crate) fn new(metrics: Arc<GfeMetrics>) -> Self {
        HealthMetrics(metrics)
    }
}

/// The labels of a backend's health series. The backend is `host:port` as
/// written, an IPv6 literal unbracketed.
fn labels(pool: &str, host: &str, port: u16) -> BackendLabels {
    BackendLabels {
        pool: pool.to_string(),
        backend: format!("{host}:{port}"),
    }
}

impl HealthObserver for HealthMetrics {
    fn probe_finished(&self, elapsed: Duration) {
        self.0
            .control
            .health_check_duration_seconds
            .observe(elapsed.as_secs_f64());
    }

    fn status_changed(&self, pool: &str, host: &str, port: u16, status: HealthStatus) {
        let labels = labels(pool, host, port);
        let control = &self.0.control;
        control
            .backend_health_status
            .get_or_create(&labels)
            .set(i64::from(status == HealthStatus::Healthy));
        control
            .backend_draining
            .get_or_create(&labels)
            .set(i64::from(status == HealthStatus::Draining));
    }

    fn backend_left(&self, pool: &str, host: &str, port: u16) {
        let labels = labels(pool, host, port);
        let control = &self.0.control;
        control.backend_health_status.remove(&labels);
        control.backend_draining.remove(&labels);
    }
}

#[cfg(test)]
#[path = "health_test.rs"]
mod tests;
