use super::*;
use crate::mock_backend;
use gfe_config::{LbPolicy, PoolId, ProbeType, Scheme, Upstream};
use std::time::Duration;

/// The shortest interval the validator accepts.
const INTERVAL: Duration = Duration::from_millis(100);

fn fast_cfg() -> HealthCheckConfig {
    HealthCheckConfig {
        probe_type: ProbeType::Http,
        interval: INTERVAL,
        timeout: Duration::from_millis(500),
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

/// Whether `condition` holds within a few seconds, polling it.
async fn eventually(condition: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    condition()
}

/// The exported value of `metric` for the backend on `port` under `pool`.
fn series(metrics: &GfeMetrics, metric: &str, pool: &str, port: u16) -> Option<i64> {
    let prefix = format!(r#"{metric}{{pool="{pool}",backend="127.0.0.1:{port}"}} "#);
    metrics
        .encode()
        .lines()
        .find_map(|line| line.strip_prefix(&prefix)?.parse().ok())
}

#[tokio::test]
async fn marks_healthy_then_prunes() {
    let backend = mock_backend::http(200).await;
    let port = backend.port;
    let health = Arc::new(HealthMap::new(false));
    let checker = HealthChecker::new(health.clone(), Arc::new(GfeMetrics::new()));

    checker.reconcile(&[pool("127.0.0.1", port)], &HealthCheckConfig::default());
    assert_eq!(checker.active_probes(), 1);
    assert!(
        eventually(|| health.is_selectable("127.0.0.1", port)).await,
        "backend should be marked healthy"
    );

    // Reconcile with empty pools → probe pruned.
    checker.reconcile(&[], &HealthCheckConfig::default());
    assert_eq!(checker.active_probes(), 0);
}

#[tokio::test]
async fn marks_unhealthy_when_down() {
    let port = mock_backend::closed_port().await;
    let health = Arc::new(HealthMap::new(true)); // optimistic until proven down
    let checker = HealthChecker::new(health.clone(), Arc::new(GfeMetrics::new()));

    checker.reconcile(&[pool("127.0.0.1", port)], &HealthCheckConfig::default());

    assert!(
        eventually(|| !health.is_selectable("127.0.0.1", port)).await,
        "backend should be marked unhealthy"
    );
    checker.stop_all();
}

/// A backend in two pools is probed once, and reported under both.
#[tokio::test]
async fn probes_a_backend_shared_by_two_pools_once() {
    let backend = mock_backend::http(200).await;
    let port = backend.port;
    let metrics = Arc::new(GfeMetrics::new());
    let checker = HealthChecker::new(Arc::new(HealthMap::new(false)), metrics.clone());
    let first = pool("127.0.0.1", port);
    let second = UpstreamPool {
        id: PoolId("q".into()),
        ..first.clone()
    };

    checker.reconcile(&[first, second], &HealthCheckConfig::default());

    assert_eq!(checker.active_probes(), 1);
    assert!(
        eventually(|| {
            series(&metrics, "gfe_backend_health_status", "p", port) == Some(1)
                && series(&metrics, "gfe_backend_health_status", "q", port) == Some(1)
        })
        .await
    );
    checker.stop_all();
}

/// A health check changed in the dynamic config must take effect on
/// reload, not only for backends added afterwards.
#[tokio::test]
async fn restarts_the_probe_of_a_backend_whose_check_changed() {
    let backend = mock_backend::http(200).await;
    let port = backend.port;
    let health = Arc::new(HealthMap::new(false));
    let checker = HealthChecker::new(health.clone(), Arc::new(GfeMetrics::new()));
    let mut pool = pool("127.0.0.1", port);
    checker.reconcile(std::slice::from_ref(&pool), &HealthCheckConfig::default());
    assert!(eventually(|| health.is_selectable("127.0.0.1", port)).await);

    // The backend answers 200; a check expecting 204 must now fail it.
    pool.health_check = Some(HealthCheckConfig {
        expected_status: 204,
        ..fast_cfg()
    });
    checker.reconcile(std::slice::from_ref(&pool), &HealthCheckConfig::default());

    assert!(
        eventually(|| !health.is_selectable("127.0.0.1", port)).await,
        "the changed check was never applied"
    );
    assert_eq!(checker.active_probes(), 1);
    checker.stop_all();
}

#[tokio::test]
async fn removes_the_series_of_a_removed_backend() {
    let backend = mock_backend::http(200).await;
    let port = backend.port;
    let metrics = Arc::new(GfeMetrics::new());
    let checker = HealthChecker::new(Arc::new(HealthMap::new(false)), metrics.clone());
    checker.reconcile(&[pool("127.0.0.1", port)], &HealthCheckConfig::default());
    assert!(
        eventually(|| series(&metrics, "gfe_backend_health_status", "p", port).is_some()).await
    );

    checker.reconcile(&[], &HealthCheckConfig::default());

    let exported = metrics.encode();
    assert!(
        !exported.contains(&format!("127.0.0.1:{port}")),
        "{exported}"
    );
}

#[tokio::test]
async fn reports_a_backend_under_the_pool_it_moved_to() {
    let backend = mock_backend::http(200).await;
    let port = backend.port;
    let metrics = Arc::new(GfeMetrics::new());
    let checker = HealthChecker::new(Arc::new(HealthMap::new(false)), metrics.clone());
    let mut moved = pool("127.0.0.1", port);
    checker.reconcile(std::slice::from_ref(&moved), &HealthCheckConfig::default());
    assert!(
        eventually(|| series(&metrics, "gfe_backend_health_status", "p", port).is_some()).await
    );

    moved.id = PoolId("q".into());
    checker.reconcile(std::slice::from_ref(&moved), &HealthCheckConfig::default());

    assert!(
        eventually(|| series(&metrics, "gfe_backend_health_status", "q", port).is_some()).await,
        "no series under the new pool"
    );
    let exported = metrics.encode();
    assert!(!exported.contains(r#"pool="p""#), "{exported}");
    checker.stop_all();
}

/// A backend whose answer flips is followed through every state, in the
/// health map and in the metrics, end to end through real probes.
#[tokio::test]
async fn follows_a_backend_through_every_state() {
    let backend = mock_backend::http(200).await;
    let port = backend.port;
    let health = Arc::new(HealthMap::new(false));
    let metrics = Arc::new(GfeMetrics::new());
    let checker = HealthChecker::new(health.clone(), metrics.clone());
    let mut pool = pool("127.0.0.1", port);
    pool.health_check = Some(HealthCheckConfig {
        healthy_threshold: 2,
        unhealthy_threshold: 2,
        drain_status: Some(503),
        ..fast_cfg()
    });
    // The health map and the metrics are written one after the other: a
    // state is reached when both show it.
    let reached = |status: HealthStatus, healthy: i64, draining: i64| {
        health.get("127.0.0.1", port) == status
            && series(&metrics, "gfe_backend_health_status", "p", port) == Some(healthy)
            && series(&metrics, "gfe_backend_draining", "p", port) == Some(draining)
    };

    assert_eq!(health.get("127.0.0.1", port), HealthStatus::Unknown);
    checker.reconcile(std::slice::from_ref(&pool), &HealthCheckConfig::default());
    assert!(eventually(|| reached(HealthStatus::Healthy, 1, 0)).await);

    backend.answer(500);
    assert!(eventually(|| reached(HealthStatus::Unhealthy, 0, 0)).await);

    backend.answer(503);
    assert!(eventually(|| reached(HealthStatus::Draining, 0, 1)).await);

    backend.answer(200);
    assert!(eventually(|| reached(HealthStatus::Healthy, 1, 0)).await);

    checker.stop_all();
}

#[tokio::test]
async fn times_every_probe() {
    let backend = mock_backend::http(200).await;
    let metrics = Arc::new(GfeMetrics::new());
    let checker = HealthChecker::new(Arc::new(HealthMap::new(false)), metrics.clone());

    checker.reconcile(
        &[pool("127.0.0.1", backend.port)],
        &HealthCheckConfig::default(),
    );

    assert!(
        eventually(|| {
            metrics.encode().lines().any(|line| {
                line.starts_with("gfe_health_check_duration_seconds_count ")
                    && !line.ends_with(" 0")
            })
        })
        .await
    );
    checker.stop_all();
}
