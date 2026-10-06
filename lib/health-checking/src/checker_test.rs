use super::*;
use crate::mock_backend;

/// A short interval, so that the tests see several probes quickly.
const INTERVAL: Duration = Duration::from_millis(100);

/// An HTTP probe of `/healthz` expecting `expected_status`, draining on
/// `drain_status`.
fn http(expected_status: u16, drain_status: Option<u16>) -> ProbeKind {
    ProbeKind::Http {
        path: "/healthz".into(),
        expected_status,
        drain_status,
        tls: false,
    }
}

fn fast_check() -> CheckSpec {
    CheckSpec {
        probe: http(200, None),
        interval: INTERVAL,
        timeout: Duration::from_millis(500),
        healthy_threshold: 1,
        unhealthy_threshold: 2,
    }
}

fn pool(host: &str, port: u16) -> CheckedPool {
    CheckedPool {
        id: "p".into(),
        check: fast_check(),
        backends: vec![(host.into(), port)],
    }
}

/// A checker over a fresh health map, writing to fresh metrics.
fn checker(
    assume_healthy_when_unknown: bool,
) -> (Arc<HealthChecker>, Arc<HealthMap>, Arc<GfeMetrics>) {
    let health = Arc::new(HealthMap::new(assume_healthy_when_unknown));
    let metrics = Arc::new(GfeMetrics::new());
    let checker = HealthChecker::new(health.clone(), metrics.clone());
    (checker, health, metrics)
}

/// The exported value of `metric` for the backend on `port` under `pool`.
fn series(metrics: &GfeMetrics, metric: &str, pool: &str, port: u16) -> Option<i64> {
    let prefix = format!(r#"{metric}{{pool="{pool}",backend="127.0.0.1:{port}"}} "#);
    metrics
        .encode()
        .lines()
        .find_map(|line| line.strip_prefix(&prefix)?.parse().ok())
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

#[tokio::test]
async fn marks_healthy_then_prunes() {
    let backend = mock_backend::http(200).await;
    let port = backend.port;
    let (checker, health, _) = checker(false);

    checker.reconcile(&[pool("127.0.0.1", port)]);
    assert_eq!(checker.active_probes(), 1);
    assert!(
        eventually(|| health.is_selectable("127.0.0.1", port)).await,
        "backend should be marked healthy"
    );

    // Reconcile with empty pools → probe pruned.
    checker.reconcile(&[]);
    assert_eq!(checker.active_probes(), 0);
}

#[tokio::test]
async fn marks_unhealthy_when_down() {
    let port = mock_backend::closed_port().await;
    let (checker, health, _) = checker(true); // optimistic until proven down

    checker.reconcile(&[pool("127.0.0.1", port)]);

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
    let (checker, _, metrics) = checker(false);
    let first = pool("127.0.0.1", port);
    let second = CheckedPool {
        id: "q".into(),
        ..first.clone()
    };

    checker.reconcile(&[first, second]);

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

/// A changed check takes effect on the next reconcile, not only for
/// backends added afterwards.
#[tokio::test]
async fn restarts_the_probe_of_a_backend_whose_check_changed() {
    let backend = mock_backend::http(200).await;
    let port = backend.port;
    let (checker, health, _) = checker(false);
    let mut pool = pool("127.0.0.1", port);
    checker.reconcile(std::slice::from_ref(&pool));
    assert!(eventually(|| health.is_selectable("127.0.0.1", port)).await);

    // The backend answers 200; a check expecting 204 must now fail it.
    pool.check.probe = http(204, None);
    checker.reconcile(std::slice::from_ref(&pool));

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
    let (checker, _, metrics) = checker(false);
    checker.reconcile(&[pool("127.0.0.1", port)]);
    assert!(
        eventually(|| series(&metrics, "gfe_backend_health_status", "p", port).is_some()).await
    );

    checker.reconcile(&[]);

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
    let (checker, _, metrics) = checker(false);
    let mut moved = pool("127.0.0.1", port);
    checker.reconcile(std::slice::from_ref(&moved));
    assert!(
        eventually(|| series(&metrics, "gfe_backend_health_status", "p", port).is_some()).await
    );

    moved.id = "q".into();
    checker.reconcile(std::slice::from_ref(&moved));

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
    let (checker, health, metrics) = checker(false);
    let mut pool = pool("127.0.0.1", port);
    pool.check = CheckSpec {
        probe: http(200, Some(503)),
        healthy_threshold: 2,
        unhealthy_threshold: 2,
        ..fast_check()
    };
    // The health map and the metrics are written one after the other: a
    // state is reached when both show it.
    let reached = |status: HealthStatus, healthy: i64, draining: i64| {
        health.get("127.0.0.1", port) == status
            && series(&metrics, "gfe_backend_health_status", "p", port) == Some(healthy)
            && series(&metrics, "gfe_backend_draining", "p", port) == Some(draining)
    };

    assert_eq!(health.get("127.0.0.1", port), HealthStatus::Unknown);
    checker.reconcile(std::slice::from_ref(&pool));
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
    let (checker, _, metrics) = checker(false);

    checker.reconcile(&[pool("127.0.0.1", backend.port)]);

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
