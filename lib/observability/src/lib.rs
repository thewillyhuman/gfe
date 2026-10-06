//! What a GFE node tells about itself: its metrics, registered here and
//! exposed in the Prometheus text format, and its log.

pub mod control_metrics;
pub mod kernel_metrics;
pub mod logging;
pub mod process_metrics;
pub mod proxy_metrics;

pub use control_metrics::{BackendLabels, ControlMetrics, SniLabel};
pub use kernel_metrics::{BackendLabel, ClientEndingLabels, KernelMetrics, UpstreamEndingLabels};
pub use logging::{Log, LogSettings};
pub use process_metrics::{LogDestinationLabel, ProcessMetrics};
/// Counter and gauge handles, for callers that hold one series of a family.
pub use prometheus_client::metrics::counter::Counter;
pub use prometheus_client::metrics::gauge::Gauge;
pub use proxy_metrics::{
    AbortLabels, CloseLabels, GrpcLabels, ListenerLabel, PoolLabel, ProxyMetrics, RejectLabel,
    RequestLabels, RouteLabels, TlsFailureLabel, TlsLabels, TlsResultLabel, UpstreamDurationLabels,
    UpstreamErrorLabels, UpstreamLabels,
};

use prometheus_client::registry::Registry;
use std::collections::HashSet;
use std::sync::Mutex;

/// Global metrics registry shared across the application.
pub struct GfeMetrics {
    pub registry: Mutex<Registry>,
    pub proxy: ProxyMetrics,
    pub control: ControlMetrics,
    pub process: ProcessMetrics,
    pub kernel: KernelMetrics,
}

impl GfeMetrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();
        let proxy = ProxyMetrics::register(&mut registry);
        let control = ControlMetrics::register(&mut registry);
        let process = ProcessMetrics::register(&mut registry);
        let kernel = KernelMetrics::register(&mut registry);
        GfeMetrics {
            registry: Mutex::new(registry),
            proxy,
            control,
            process,
            kernel,
        }
    }

    /// Encode all metrics in the Prometheus text exposition format.
    pub fn encode(&self) -> String {
        self.process.refresh();
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

/// `exposition` without the family metadata (`# HELP`, `# TYPE`, `# UNIT`)
/// of its histograms. Their `_bucket`, `_sum` and `_count` series are then
/// series of no declared type, which is all a query over them needs.
///
/// It is for collectors that rebuild a scraped histogram in a model of
/// their own and get it wrong, so that it is lost further on. Given series
/// of no declared type, they pass them on as they are.
pub fn without_histogram_metadata(exposition: &str) -> String {
    let histograms: HashSet<&str> = exposition
        .lines()
        .filter_map(|line| line.strip_prefix("# TYPE ")?.strip_suffix(" histogram"))
        .collect();
    let describes_a_histogram = |line: &str| {
        ["# HELP ", "# TYPE ", "# UNIT "].iter().any(|prefix| {
            line.strip_prefix(prefix)
                .and_then(|rest| rest.split(' ').next())
                .is_some_and(|family| histograms.contains(family))
        })
    };
    let mut untyped = String::with_capacity(exposition.len());
    for line in exposition
        .lines()
        .filter(|line| !describes_a_histogram(line))
    {
        untyped.push_str(line);
        untyped.push('\n');
    }
    untyped
}

#[cfg(test)]
#[path = "lib_test.rs"]
mod tests;
