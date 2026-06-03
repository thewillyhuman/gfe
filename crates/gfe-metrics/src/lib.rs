//! Metrics registration and Prometheus exposition for GFE.

pub mod control_metrics;
pub mod proxy_metrics;

pub use control_metrics::{BackendLabels, ControlMetrics, SniLabel};
pub use proxy_metrics::{
    ListenerLabel, ProxyMetrics, RejectLabel, RequestDurationLabels, RequestLabels, TlsResultLabel,
    UpstreamDurationLabels, UpstreamLabels,
};

use prometheus_client::registry::Registry;
use std::sync::Mutex;

/// Global metrics registry shared across the application.
pub struct GfeMetrics {
    pub registry: Mutex<Registry>,
    pub proxy: ProxyMetrics,
    pub control: ControlMetrics,
}

impl GfeMetrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();
        let proxy = ProxyMetrics::register(&mut registry);
        let control = ControlMetrics::register(&mut registry);
        GfeMetrics {
            registry: Mutex::new(registry),
            proxy,
            control,
        }
    }

    /// Encode all metrics in the Prometheus text exposition format.
    pub fn encode(&self) -> String {
        let registry = self.registry.lock().expect("metrics registry poisoned");
        let mut buf = String::new();
        prometheus_client::encoding::text::encode(&mut buf, &registry).expect("encode metrics");
        buf
    }
}

impl Default for GfeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_registered_metrics() {
        let m = GfeMetrics::new();
        m.proxy.no_route.inc();
        let out = m.encode();
        assert!(out.contains("gfe_no_route"));
        assert!(out.contains("gfe_backend_health_status"));
    }
}
