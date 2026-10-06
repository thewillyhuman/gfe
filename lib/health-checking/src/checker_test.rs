use super::*;
use crate::mock_backend;
use std::sync::atomic::{AtomicUsize, Ordering};

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

/// An observer remembering the last status reported for each pool and
/// backend, forgetting those that left, and counting probes.
#[derive(Default)]
struct Recorder {
    statuses: Mutex<HashMap<(String, String), HealthStatus>>,
    probes: AtomicUsize,
}

impl Recorder {
    /// The last status reported for the backend on `127.0.0.1:port` under
    /// `pool`, unless it left.
    fn status(&self, pool: &str, port: u16) -> Option<HealthStatus> {
        let key = (pool.to_string(), format!("127.0.0.1:{port}"));
        self.statuses.lock().unwrap().get(&key).copied()
    }
}

impl HealthObserver for Recorder {
    fn probe_finished(&self, _elapsed: Duration) {
        self.probes.fetch_add(1, Ordering::SeqCst);
    }

    fn status_changed(&self, pool: &str, host: &str, port: u16, status: HealthStatus) {
        let key = (pool.to_string(), format!("{host}:{port}"));
        self.statuses.lock().unwrap().insert(key, status);
    }

    fn backend_left(&self, pool: &str, host: &str, port: u16) {
        let key = (pool.to_string(), format!("{host}:{port}"));
        self.statuses.lock().unwrap().remove(&key);
    }
}

/// A checker over a fresh health map, reporting to a fresh recorder.
fn checker(
    assume_healthy_when_unknown: bool,
) -> (Arc<HealthChecker>, Arc<HealthMap>, Arc<Recorder>) {
    let health = Arc::new(HealthMap::new(assume_healthy_when_unknown));
    let recorder = Arc::new(Recorder::default());
    let checker = HealthChecker::new(health.clone(), recorder.clone());
    (checker, health, recorder)
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
    let (checker, _, recorder) = checker(false);
    let first = pool("127.0.0.1", port);
    let second = CheckedPool {
        id: "q".into(),
        ..first.clone()
    };

    checker.reconcile(&[first, second]);

    assert_eq!(checker.active_probes(), 1);
    assert!(
        eventually(|| {
            recorder.status("p", port) == Some(HealthStatus::Healthy)
                && recorder.status("q", port) == Some(HealthStatus::Healthy)
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
async fn tells_the_observer_a_removed_backend_left() {
    let backend = mock_backend::http(200).await;
    let port = backend.port;
    let (checker, _, recorder) = checker(false);
    checker.reconcile(&[pool("127.0.0.1", port)]);
    assert!(eventually(|| recorder.status("p", port).is_some()).await);

    checker.reconcile(&[]);

    assert_eq!(recorder.status("p", port), None);
}

#[tokio::test]
async fn reports_a_backend_under_the_pool_it_moved_to() {
    let backend = mock_backend::http(200).await;
    let port = backend.port;
    let (checker, _, recorder) = checker(false);
    let mut moved = pool("127.0.0.1", port);
    checker.reconcile(std::slice::from_ref(&moved));
    assert!(eventually(|| recorder.status("p", port).is_some()).await);

    moved.id = "q".into();
    checker.reconcile(std::slice::from_ref(&moved));

    assert!(
        eventually(|| recorder.status("q", port).is_some()).await,
        "nothing reported under the new pool"
    );
    assert_eq!(recorder.status("p", port), None);
    checker.stop_all();
}

/// A backend whose answer flips is followed through every state, in the
/// health map and by the observer, end to end through real probes.
#[tokio::test]
async fn follows_a_backend_through_every_state() {
    let backend = mock_backend::http(200).await;
    let port = backend.port;
    let (checker, health, recorder) = checker(false);
    let mut pool = pool("127.0.0.1", port);
    pool.check = CheckSpec {
        probe: http(200, Some(503)),
        healthy_threshold: 2,
        unhealthy_threshold: 2,
        ..fast_check()
    };
    // The health map and the observer are told one after the other: a
    // state is reached when both have it.
    let reached = |status: HealthStatus| {
        health.get("127.0.0.1", port) == status && recorder.status("p", port) == Some(status)
    };

    assert_eq!(health.get("127.0.0.1", port), HealthStatus::Unknown);
    checker.reconcile(std::slice::from_ref(&pool));
    assert!(eventually(|| reached(HealthStatus::Healthy)).await);

    backend.answer(500);
    assert!(eventually(|| reached(HealthStatus::Unhealthy)).await);

    backend.answer(503);
    assert!(eventually(|| reached(HealthStatus::Draining)).await);

    backend.answer(200);
    assert!(eventually(|| reached(HealthStatus::Healthy)).await);

    checker.stop_all();
}

#[tokio::test]
async fn tells_the_observer_of_every_probe() {
    let backend = mock_backend::http(200).await;
    let (checker, _, recorder) = checker(false);

    checker.reconcile(&[pool("127.0.0.1", backend.port)]);

    assert!(eventually(|| recorder.probes.load(Ordering::SeqCst) > 0).await);
    checker.stop_all();
}
