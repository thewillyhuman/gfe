//! The health checker: reconciles a set of probe loops against the configured
//! pools, deduplicating by `(host, port)`, and writes committed transitions to
//! the shared health map.

use crate::HealthMap;
use crate::HealthStatus;
use crate::probe::make_probe;
use crate::state_machine::BackendHealth;
use gfe_config::{HealthCheckConfig, Scheme, UpstreamPool};
use gfe_observability::{BackendLabels, GfeMetrics};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::task::JoinHandle;

type Key = (String, u16);

/// What decides how a backend is probed: the check, and the scheme of the
/// pool it belongs to (a gRPC probe uses TLS for `https` pools).
type Check = (HealthCheckConfig, Scheme);

/// A running probe loop, the check it was started with, and the pools it
/// reports the backend's health under.
struct Running {
    check: Check,
    pools: Vec<String>,
    task: JoinHandle<()>,
}

/// Runs and supervises per-backend probe loops.
pub struct HealthChecker {
    health: Arc<HealthMap>,
    metrics: Arc<GfeMetrics>,
    tasks: Mutex<HashMap<Key, Running>>,
}

impl HealthChecker {
    /// A checker writing committed transitions to `health` and the backend
    /// health series to `metrics`. It probes nothing until [`reconcile`].
    ///
    /// [`reconcile`]: HealthChecker::reconcile
    pub fn new(health: Arc<HealthMap>, metrics: Arc<GfeMetrics>) -> Arc<Self> {
        Arc::new(HealthChecker {
            health,
            metrics,
            tasks: Mutex::new(HashMap::new()),
        })
    }

    /// Start probes for backends in `pools`, stop probes for backends no
    /// longer present, and restart those whose check or list of pools
    /// changed. Deduplicates by `(host, port)`; the first pool's
    /// health-check config wins for a shared backend.
    ///
    /// The health series of a backend under a pool it no longer belongs to
    /// are removed, so alerts do not fire for objects that are gone.
    ///
    /// A restarted probe keeps the backend's current status until its own
    /// thresholds say otherwise, so changing a check does not flap traffic.
    ///
    /// Must be called within a Tokio runtime: the probe loops are tasks.
    pub fn reconcile(self: &Arc<Self>, pools: &[UpstreamPool], defaults: &HealthCheckConfig) {
        let mut desired: HashMap<Key, (Check, Vec<String>)> = HashMap::new();
        for p in pools {
            let cfg = p.health_check.clone().unwrap_or_else(|| defaults.clone());
            for u in &p.upstreams {
                let key = (u.host.clone(), u.port);
                let entry = desired
                    .entry(key)
                    .or_insert_with(|| ((cfg.clone(), p.scheme), Vec::new()));
                entry.1.push(p.id.to_string());
            }
        }

        let mut tasks = self.tasks.lock().expect("health tasks poisoned");

        // Stop probes for removed backends, changed checks and changed pools.
        tasks.retain(|key, running| {
            let wanted = desired.get(key);
            let unchanged = wanted
                .is_some_and(|(check, pools)| *check == running.check && *pools == running.pools);
            if !unchanged {
                running.task.abort();
                let kept: &[String] = wanted.map_or(&[], |(_, pools)| pools);
                for pool in running.pools.iter().filter(|p| !kept.contains(p)) {
                    self.remove_series(pool, key);
                }
            }
            unchanged
        });

        // Start probes for new backends, changed checks and changed pools.
        for (key, (check, pools)) in desired {
            if tasks.contains_key(&key) {
                continue;
            }
            let this = self.clone();
            let (host, port) = key.clone();
            let task = tokio::spawn({
                let (check, pools) = (check.clone(), pools.clone());
                async move { this.run_probe(host, port, check, pools).await }
            });
            tasks.insert(key, Running { check, pools, task });
        }
    }

    /// Stop exporting the health of backend `(host, port)` under `pool`.
    fn remove_series(&self, pool: &str, (host, port): &Key) {
        let labels = BackendLabels {
            pool: pool.to_string(),
            backend: format!("{host}:{port}"),
        };
        let control = &self.metrics.control;
        control.backend_health_status.remove(&labels);
        control.backend_draining.remove(&labels);
    }

    /// Abort all probe loops.
    pub fn stop_all(&self) {
        let mut tasks = self.tasks.lock().expect("health tasks poisoned");
        for (_, running) in tasks.drain() {
            running.task.abort();
        }
    }

    /// Number of running probe loops.
    pub fn active_probes(&self) -> usize {
        self.tasks.lock().expect("health tasks poisoned").len()
    }

    async fn run_probe(
        self: Arc<Self>,
        host: String,
        port: u16,
        (cfg, scheme): Check,
        pools: Vec<String>,
    ) {
        let probe = make_probe(&cfg, scheme);
        let mut bh = BackendHealth::default();
        let backend = format!("{host}:{port}");
        loop {
            let start = Instant::now();
            let ok = probe.check(&host, port, cfg.timeout).await;
            self.metrics
                .control
                .health_check_duration_seconds
                .observe(start.elapsed().as_secs_f64());

            if let Some(new) = bh.record(ok, cfg.healthy_threshold, cfg.unhealthy_threshold) {
                self.health.set(&host, port, new);
                let healthy_val = i64::from(new == HealthStatus::Healthy);
                let draining_val = i64::from(new == HealthStatus::Draining);
                for pid in &pools {
                    let labels = BackendLabels {
                        pool: pid.clone(),
                        backend: backend.clone(),
                    };
                    self.metrics
                        .control
                        .backend_health_status
                        .get_or_create(&labels)
                        .set(healthy_val);
                    self.metrics
                        .control
                        .backend_draining
                        .get_or_create(&labels)
                        .set(draining_val);
                }
                tracing::info!(backend = %backend, status = ?new, "backend health transition");
            }

            tokio::time::sleep(cfg.interval).await;
        }
    }
}

#[cfg(test)]
#[path = "checker_test.rs"]
mod tests;
