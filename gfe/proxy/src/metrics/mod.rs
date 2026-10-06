//! What a node tells about itself in numbers: every `gfe_*` family (and
//! the standard `process_*` ones), registered in one registry and exposed
//! by the node in the Prometheus text format.
//!
//! - [`ProxyMetrics`]: client connections, TLS handshakes, requests, and
//!   the requests sent on to backends.
//! - [`ControlMetrics`]: backend health, the dynamic config and its
//!   reloads, upgrades, certificate expiry.
//! - [`KernelMetrics`]: the kernel's view of the node's TCP connections.
//! - [`ProcessMetrics`]: the process, its async runtime and its log.

mod control;
mod kernel;
mod process;
mod proxy;

pub use control::{BackendLabels, ControlMetrics, SniLabel};
pub use kernel::{BackendLabel, ClientEndingLabels, KernelMetrics, UpstreamEndingLabels};
pub use process::{LogDestinationLabel, ProcessMetrics};
pub use proxy::{
    AbortLabels, CloseLabels, GrpcLabels, ListenerLabel, PoolLabel, ProxyMetrics, RejectLabel,
    RequestLabels, RouteLabels, TlsFailureLabel, TlsLabels, TlsResultLabel, UpstreamDurationLabels,
    UpstreamErrorLabels, UpstreamLabels,
};

use netkit_observability::Registry;
use std::sync::Mutex;

/// Global metrics registry shared across the application.
pub struct GfeMetrics {
    /// Every family below, as the node exposes them.
    pub registry: Mutex<Registry>,
    pub proxy: ProxyMetrics,
    pub control: ControlMetrics,
    pub process: ProcessMetrics,
    pub kernel: KernelMetrics,
}

impl GfeMetrics {
    /// Every family registered, nothing counted yet.
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
        netkit_observability::encode(&registry)
    }
}

impl Default for GfeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "mod_test.rs"]
mod tests;
