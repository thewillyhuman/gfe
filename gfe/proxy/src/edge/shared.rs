//! What every connection the edge serves shares: where it is counted, the
//! limits and timeouts it is held to, and the sources of what the edge
//! cannot observe itself (the kernel's accept queue, the certificate
//! resolver's misses).
//!
//! Whether the node drains is not kept here: `netkit_listen::Drain` is the
//! one place that knows.

use crate::metrics::GfeMetrics;
use gfe_config::{LimitsConfig, TimeoutsConfig};
use netkit_tls::SniResolver;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// What only the kernel knows about a connection the node has just accepted.
/// Serving does not care where the answer comes from; the node provides an
/// implementation when it has one (eBPF) and none otherwise.
pub trait AcceptQueue: Send + Sync {
    /// How long the connection between `local` and `peer` had been waiting,
    /// its handshake complete, when `accept` returned it. `None` if unknown.
    ///
    /// Both addresses are given in their canonical form: an IPv4 client of a
    /// dual-stack socket is `1.2.3.4`, not `::ffff:1.2.3.4`.
    fn waited(&self, local: SocketAddr, peer: SocketAddr) -> Option<Duration>;
}

/// What every connection a node serves shares.
pub struct Shared {
    metrics: Arc<GfeMetrics>,
    limits: LimitsConfig,
    timeouts: TimeoutsConfig,
    accept_queue: Option<Arc<dyn AcceptQueue>>,
    sni_resolver: Option<Arc<SniResolver>>,
    /// The resolver's miss count when it was last copied to the metric.
    sni_misses_exported: AtomicU64,
}

impl Shared {
    /// The state shared by connections counted in `metrics`, held to
    /// `limits` and `timeouts`. Publishes the connection limits as gauges.
    pub fn new(metrics: Arc<GfeMetrics>, limits: LimitsConfig, timeouts: TimeoutsConfig) -> Self {
        // Published next to the gauges they bound, so saturation is a ratio
        // of two series rather than a number hardcoded in a dashboard.
        metrics
            .proxy
            .connections_limit
            .set(i64::try_from(limits.max_connections).unwrap_or(i64::MAX));
        metrics
            .proxy
            .listener_connections_limit
            .set(i64::try_from(limits.max_connections_listener).unwrap_or(i64::MAX));
        Shared {
            metrics,
            limits,
            timeouts,
            accept_queue: None,
            sni_resolver: None,
            sni_misses_exported: AtomicU64::new(0),
        }
    }

    /// Ask `accept_queue` how long each accepted connection waited.
    pub fn with_accept_queue(mut self, accept_queue: Arc<dyn AcceptQueue>) -> Self {
        self.accept_queue = Some(accept_queue);
        self
    }

    /// Count the handshakes `resolver` found no certificate for, as
    /// `gfe_tls_sni_no_cert`. `netkit-tls` records no metric itself.
    pub fn with_sni_resolver(mut self, resolver: Arc<SniResolver>) -> Self {
        self.sni_resolver = Some(resolver);
        self
    }

    /// Where connections are counted.
    pub fn metrics(&self) -> &Arc<GfeMetrics> {
        &self.metrics
    }

    /// The limits connections are held to.
    pub fn limits(&self) -> &LimitsConfig {
        &self.limits
    }

    /// The timeouts connections are held to.
    pub fn timeouts(&self) -> &TimeoutsConfig {
        &self.timeouts
    }

    /// How long the connection between `local` and `peer` (both canonical)
    /// waited to be accepted, if the kernel's view is available and knows.
    pub fn accept_wait(&self, local: SocketAddr, peer: SocketAddr) -> Option<Duration> {
        self.accept_queue.as_ref()?.waited(local, peer)
    }

    /// Bring `gfe_tls_sni_no_cert` up to the resolver's miss count. Meant to
    /// be called after every handshake; safe to call from many connections
    /// at once, and a no-op without a resolver.
    pub fn export_sni_misses(&self) {
        let Some(resolver) = &self.sni_resolver else {
            return;
        };
        let misses = resolver.miss_count();
        // Whoever moves the mark forward counts the difference: two callers
        // racing never count the same miss twice.
        let exported = self
            .sni_misses_exported
            .fetch_max(misses, Ordering::Relaxed);
        if misses > exported {
            self.metrics.proxy.tls_sni_no_cert.inc_by(misses - exported);
        }
    }
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("limits", &self.limits)
            .field("timeouts", &self.timeouts)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "shared_test.rs"]
mod tests;
