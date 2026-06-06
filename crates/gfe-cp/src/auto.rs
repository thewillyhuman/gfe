//! Backend (de)registration automation (spec §9). Service onboarding/offboarding
//! is the high-frequency path: each call mutates desired state and marks the
//! fleet dirty, and a debouncer coalesces bursts into a single render → validate
//! → publish so a hundred backends registering at once produce one revision, not
//! a hundred.

use crate::publish::publish;
use crate::store::Store;
use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::Duration;

/// Coalesces dirty-fleet notifications and republishes them on a timer.
pub struct Debouncer {
    store: Store,
    dirty: Mutex<BTreeSet<String>>,
    window: Duration,
}

impl Debouncer {
    /// Build a debouncer that flushes at most once per `window`.
    pub fn new(store: Store, window: Duration) -> Self {
        Debouncer {
            store,
            dirty: Mutex::new(BTreeSet::new()),
            window,
        }
    }

    /// Mark a fleet as needing a republish.
    pub fn mark(&self, fleet: &str) {
        self.dirty
            .lock()
            .expect("debouncer mutex poisoned")
            .insert(fleet.to_string());
    }

    /// Publish every fleet marked dirty since the last flush. Returns the
    /// per-fleet outcome (new revision sequence, or an error string) for logging
    /// and tests.
    pub fn flush(&self) -> Vec<(String, Result<i64, String>)> {
        let fleets: Vec<String> = {
            let mut d = self.dirty.lock().expect("debouncer mutex poisoned");
            std::mem::take(&mut *d).into_iter().collect()
        };
        fleets
            .into_iter()
            .map(|f| {
                let res = publish(&self.store, &f, "backend-automation")
                    .map(|p| p.revision.seq)
                    .map_err(|e| e.to_string());
                (f, res)
            })
            .collect()
    }

    /// Run the flush loop until the process exits.
    pub async fn run(self: std::sync::Arc<Self>) {
        loop {
            tokio::time::sleep(self.window).await;
            for (fleet, res) in self.flush() {
                match res {
                    Ok(seq) => tracing::info!(%fleet, seq, "auto-published after backend change"),
                    Err(e) => tracing::warn!(%fleet, error = %e, "auto-publish failed"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::AeadSealer;
    use gfe_cp_types::{Backend, Fleet, ListenerSpec, PoolSpec, RouteActionSpec, RouteSpec};
    use gfe_types::{ListenProtocol, Scheme};
    use std::sync::Arc;

    fn seeded_store() -> Store {
        let s = Store::in_memory(Arc::new(AeadSealer::new(&[6u8; 32]).unwrap()));
        s.create_fleet(Fleet::new("f", "10.0.0.1".parse().unwrap()))
            .unwrap();
        s.put_listener(
            "f",
            ListenerSpec {
                name: "http".into(),
                address: "10.0.0.1".parse().unwrap(),
                port: 80,
                protocol: ListenProtocol::Http,
            },
        )
        .unwrap();
        s.put_pool(
            "f",
            PoolSpec {
                name: "web".into(),
                scheme: Scheme::Http,
                lb_policy: Default::default(),
                health_check: None,
                backends: vec![Backend {
                    host: "10.0.0.2".into(),
                    port: 8080,
                    weight: 1,
                    enabled: true,
                }],
            },
        )
        .unwrap();
        s.put_route(
            "f",
            RouteSpec {
                name: "r".into(),
                listener: "http".into(),
                host: "a.example.org".into(),
                path_prefix: "/".into(),
                action: RouteActionSpec::Forward("web".into()),
            },
        )
        .unwrap();
        s
    }

    #[test]
    fn bursts_coalesce_into_one_revision() {
        let store = seeded_store();
        let deb = Debouncer::new(store.clone(), Duration::from_millis(10));
        // Register three backends in a burst.
        for host in ["10.0.0.3", "10.0.0.4", "10.0.0.5"] {
            store
                .put_backend(
                    "f",
                    "web",
                    Backend {
                        host: host.into(),
                        port: 8080,
                        weight: 1,
                        enabled: true,
                    },
                )
                .unwrap();
            deb.mark("f");
        }
        let out = deb.flush();
        assert_eq!(out.len(), 1, "one fleet republished");
        assert_eq!(out[0].0, "f");
        // One revision created for the whole burst.
        assert_eq!(store.list_revisions("f").unwrap().len(), 1);
        assert_eq!(store.target_seq("f").unwrap(), Some(1));
        // It contains all four backends.
        let pools = store.fleet_state("f").unwrap().pools;
        assert_eq!(pools[0].backends.len(), 4);
    }

    #[test]
    fn flush_with_nothing_dirty_is_noop() {
        let store = seeded_store();
        let deb = Debouncer::new(store.clone(), Duration::from_millis(10));
        assert!(deb.flush().is_empty());
        assert!(store.list_revisions("f").unwrap().is_empty());
    }
}
