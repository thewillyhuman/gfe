//! The health checker: reconciles a set of probe loops against the configured
//! pools, deduplicating by `(host, port)`, and writes committed transitions to
//! the shared health map.

use crate::probe::make_probe;
use crate::state_machine::BackendHealth;
use gfe_observability::{BackendLabels, GfeMetrics};
use gfe_types::{HealthCheckConfig, HealthStatus, Scheme, UpstreamPool};
use gfe_upstream::HealthMap;
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
mod tests {
    use super::*;
    use bytes::Bytes;
    use gfe_types::{LbPolicy, PoolId, ProbeType, Scheme, Upstream};
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper::Response;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use std::time::Duration;

    async fn spawn_healthz(status: u16) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |_req| async move {
                        let mut r = Response::new(Full::new(Bytes::from("ok")));
                        *r.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
                        Ok::<_, Infallible>(r)
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });
        port
    }

    fn fast_cfg() -> HealthCheckConfig {
        HealthCheckConfig {
            probe_type: ProbeType::Http,
            interval: Duration::from_millis(30),
            timeout: Duration::from_millis(300),
            healthy_threshold: 1,
            unhealthy_threshold: 2,
            path: "/healthz".into(),
            expected_status: 200,
            drain_status: None,
        }
    }

    fn pool(host: &str, port: u16) -> UpstreamPool {
        UpstreamPool {
            id: PoolId("p".into()),
            scheme: Scheme::Http,
            lb_policy: LbPolicy::RoundRobin,
            upstreams: vec![Upstream {
                host: host.into(),
                port,
                weight: 1,
            }],
            health_check: Some(fast_cfg()),
            max_in_flight: None,
        }
    }

    #[tokio::test]
    async fn marks_healthy_then_prunes() {
        let port = spawn_healthz(200).await;
        let health = Arc::new(HealthMap::new(false));
        let metrics = Arc::new(GfeMetrics::new());
        let checker = HealthChecker::new(health.clone(), metrics);

        checker.reconcile(&[pool("127.0.0.1", port)], &HealthCheckConfig::default());
        assert_eq!(checker.active_probes(), 1);

        // Wait for at least one healthy transition.
        let mut healthy = false;
        for _ in 0..50 {
            if health.is_selectable("127.0.0.1", port) {
                healthy = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(healthy, "backend should be marked healthy");

        // Reconcile with empty pools → probe pruned.
        checker.reconcile(&[], &HealthCheckConfig::default());
        assert_eq!(checker.active_probes(), 0);
    }

    #[tokio::test]
    async fn marks_unhealthy_when_down() {
        // Bind then immediately drop to get a closed port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let health = Arc::new(HealthMap::new(true)); // optimistic until proven down
        let metrics = Arc::new(GfeMetrics::new());
        let checker = HealthChecker::new(health.clone(), metrics);
        checker.reconcile(&[pool("127.0.0.1", port)], &HealthCheckConfig::default());

        let mut down = false;
        for _ in 0..50 {
            if !health.is_selectable("127.0.0.1", port) {
                down = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(down, "backend should be marked unhealthy");
        checker.stop_all();
    }

    /// A health check changed in the dynamic config must take effect on
    /// reload, not only for backends added afterwards.
    #[tokio::test]
    async fn restarts_the_probe_of_a_backend_whose_check_changed() {
        let port = spawn_healthz(200).await;
        let health = Arc::new(HealthMap::new(false));
        let checker = HealthChecker::new(health.clone(), Arc::new(GfeMetrics::new()));
        let mut pool = pool("127.0.0.1", port);
        checker.reconcile(std::slice::from_ref(&pool), &HealthCheckConfig::default());
        for _ in 0..50 {
            if health.is_selectable("127.0.0.1", port) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(health.is_selectable("127.0.0.1", port));

        // The backend answers 200; a check expecting 204 must now fail it.
        pool.health_check = Some(HealthCheckConfig {
            expected_status: 204,
            ..fast_cfg()
        });
        checker.reconcile(std::slice::from_ref(&pool), &HealthCheckConfig::default());

        let mut failed = false;
        for _ in 0..50 {
            if !health.is_selectable("127.0.0.1", port) {
                failed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(failed, "the changed check was never applied");
        assert_eq!(checker.active_probes(), 1);
        checker.stop_all();
    }

    /// Wait until `metrics` export a health series for `pool` and `port`.
    async fn wait_for_series(metrics: &GfeMetrics, pool: &str, port: u16) -> bool {
        let series =
            format!(r#"gfe_backend_health_status{{pool="{pool}",backend="127.0.0.1:{port}"}}"#);
        for _ in 0..50 {
            if metrics.encode().contains(&series) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    #[tokio::test]
    async fn removes_the_series_of_a_removed_backend() {
        let port = spawn_healthz(200).await;
        let metrics = Arc::new(GfeMetrics::new());
        let checker = HealthChecker::new(Arc::new(HealthMap::new(false)), metrics.clone());
        checker.reconcile(&[pool("127.0.0.1", port)], &HealthCheckConfig::default());
        assert!(wait_for_series(&metrics, "p", port).await);

        checker.reconcile(&[], &HealthCheckConfig::default());

        let exported = metrics.encode();
        assert!(
            !exported.contains(&format!("127.0.0.1:{port}")),
            "{exported}"
        );
    }

    #[tokio::test]
    async fn reports_a_backend_under_the_pool_it_moved_to() {
        let port = spawn_healthz(200).await;
        let metrics = Arc::new(GfeMetrics::new());
        let checker = HealthChecker::new(Arc::new(HealthMap::new(false)), metrics.clone());
        let mut moved = pool("127.0.0.1", port);
        checker.reconcile(std::slice::from_ref(&moved), &HealthCheckConfig::default());
        assert!(wait_for_series(&metrics, "p", port).await);

        moved.id = PoolId("q".into());
        checker.reconcile(std::slice::from_ref(&moved), &HealthCheckConfig::default());

        assert!(
            wait_for_series(&metrics, "q", port).await,
            "no series under the new pool"
        );
        let exported = metrics.encode();
        assert!(!exported.contains(r#"pool="p""#), "{exported}");
        checker.stop_all();
    }
}
