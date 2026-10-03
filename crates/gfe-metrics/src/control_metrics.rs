use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;

/// `pool` + `backend` labels for per-backend gauges.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BackendLabels {
    pub pool: String,
    pub backend: String,
}

/// `sni` label for per-certificate expiry.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SniLabel {
    pub sni: String,
}

/// Control-plane metrics.
#[derive(Clone)]
pub struct ControlMetrics {
    pub backend_health_status: Family<BackendLabels, Gauge>,
    pub backend_draining: Family<BackendLabels, Gauge>,
    pub health_check_duration_seconds: Histogram,
    pub config_last_reload_timestamp: Gauge,
    pub config_reload_errors: Counter,
    /// 1 while the last attempt to load the dynamic config failed (a
    /// rejected reload, or a start from the cache), 0 once one succeeded.
    /// Unlike the error counter, it stays up for as long as the node runs a
    /// config other than the deployed one.
    pub config_reload_failed: Gauge,
    pub config_from_cache: Gauge,
    pub upgrade_failures: Counter,
    pub cert_expiry_timestamp: Family<SniLabel, Gauge>,
    pub active_routes: Gauge,
    pub active_pools: Gauge,
}

impl ControlMetrics {
    pub fn register(registry: &mut Registry) -> Self {
        let m = ControlMetrics {
            backend_health_status: Family::default(),
            backend_draining: Family::default(),
            health_check_duration_seconds: Histogram::new([
                0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0,
            ]),
            config_last_reload_timestamp: Gauge::default(),
            config_reload_errors: Counter::default(),
            config_reload_failed: Gauge::default(),
            config_from_cache: Gauge::default(),
            upgrade_failures: Counter::default(),
            cert_expiry_timestamp: Family::default(),
            active_routes: Gauge::default(),
            active_pools: Gauge::default(),
        };

        registry.register(
            "gfe_backend_health_status",
            "1=HEALTHY, 0=otherwise, per backend",
            m.backend_health_status.clone(),
        );
        registry.register(
            "gfe_backend_draining",
            "1 if backend is in lame-duck DRAINING",
            m.backend_draining.clone(),
        );
        registry.register(
            "gfe_health_check_duration_seconds",
            "Health probe round-trip time",
            m.health_check_duration_seconds.clone(),
        );
        registry.register(
            "gfe_config_last_reload_timestamp",
            "Unix time of last successful dynamic-config reload",
            m.config_last_reload_timestamp.clone(),
        );
        registry.register(
            "gfe_config_reload_errors",
            "Failed reloads (old snapshot kept)",
            m.config_reload_errors.clone(),
        );
        registry.register(
            "gfe_config_reload_failed",
            "Whether the last attempt to load the dynamic config failed (1) or succeeded (0)",
            m.config_reload_failed.clone(),
        );
        registry.register(
            "gfe_config_from_cache",
            "Whether the node serves its last-known-good cache (1) because the deployed dynamic config was unusable at startup",
            m.config_from_cache.clone(),
        );
        registry.register(
            "gfe_upgrade_failures",
            "In-place upgrades that failed (the node went on serving as it was)",
            m.upgrade_failures.clone(),
        );
        registry.register(
            "gfe_cert_expiry_timestamp",
            "Certificate not-after Unix time per SNI",
            m.cert_expiry_timestamp.clone(),
        );
        registry.register(
            "gfe_active_routes",
            "Routes in the current snapshot",
            m.active_routes.clone(),
        );
        registry.register(
            "gfe_active_pools",
            "Pools in the current snapshot",
            m.active_pools.clone(),
        );

        m
    }
}
