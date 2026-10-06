//! Keeping a running node in step with its dynamic config: the config it
//! starts from, the reloads when the file or a certificate it names
//! changes, the listeners and health checks that follow, and the
//! last-known-good cache.

use crate::listener::Listeners;
use crate::proxy::{App, State};
use crate::reload::applier::{install, prepare};
use crate::reload::{ReloadError, cache, watcher};
use gfe_config::{DynamicConfig, HealthCheckConfig, NodeConfig, load_dynamic_config};
use netkit_health_checking::HealthChecker;
use netkit_tls::CertFiles;
use notify::RecommendedWatcher;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::task::JoinHandle;

/// How often the certificate files are checked for a rotation. Certificates
/// are replaced in place without the dynamic config changing, so the config
/// watcher alone would never notice.
pub const CERT_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Keeps one node in step with its dynamic config, from [`start`] until
/// [`shutdown`] (or until dropped).
///
/// [`start`]: Controller::start
/// [`shutdown`]: Controller::shutdown
pub struct Controller {
    reloader: Arc<Reloader>,
    /// Watching lasts as long as this is kept.
    watcher: Mutex<Option<RecommendedWatcher>>,
    cert_poller: JoinHandle<()>,
}

impl std::fmt::Debug for Controller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Controller")
            .field("config_file", &self.reloader.config_file)
            .finish_non_exhaustive()
    }
}

impl Controller {
    /// Apply the config a starting node serves to `state`, with its
    /// listeners in `listeners`, start its health checks, and from then on
    /// follow the dynamic config file and the certificate files it names
    /// (checked every `cert_poll_interval`, normally
    /// [`CERT_POLL_INTERVAL`]).
    ///
    /// The config a node starts from is the deployed dynamic config or, if
    /// that cannot be read, is invalid or cannot be applied, the
    /// last-known-good cache (`gfe_config_from_cache` then says so). A node
    /// that restarts while its config is broken thus keeps serving what it
    /// served before, exactly as a running node does when it rejects a
    /// reload. Fails, with nothing applied, if neither can be used.
    ///
    /// Must be called from within a Tokio runtime.
    pub fn start(
        state: Arc<State>,
        listeners: Arc<Listeners<App>>,
        node: &NodeConfig,
        cert_poll_interval: Duration,
    ) -> Result<Controller, ReloadError> {
        let checker = HealthChecker::new(Arc::clone(state.health()), Arc::clone(state.metrics()));
        let reloader = Arc::new(Reloader {
            state,
            listeners,
            checker,
            config_file: node.control_plane.config_file.clone(),
            cache_file: node.control_plane.local_cache.clone(),
            defaults: node.health_check_defaults.clone(),
            tracked: Mutex::new(Tracked {
                cert_files: CertFiles::default(),
                following: false,
            }),
        });

        // Watching first: a file that cannot be watched fails the start
        // before any socket is bound. A change seen before the first config
        // is applied waits for it, then is applied in turn.
        let watcher = watcher::watch(&reloader.config_file, node.control_plane.reload_debounce, {
            let reloader = Arc::clone(&reloader);
            move || reloader.reload()
        })?;

        let config = reloader.apply_initial()?;
        reloader
            .checker
            .reconcile(&config.pools, &reloader.defaults);
        tracing::info!(
            file = %reloader.config_file.display(),
            "watching the dynamic config for changes"
        );

        let cert_poller = tokio::spawn({
            let reloader = Arc::clone(&reloader);
            // The files were read just now, so the first check is one
            // interval out.
            let first = tokio::time::Instant::now() + cert_poll_interval;
            let mut ticker = tokio::time::interval_at(first, cert_poll_interval);
            async move {
                loop {
                    ticker.tick().await;
                    reloader.reload_if_certificates_changed();
                }
            }
        });

        Ok(Controller {
            reloader,
            watcher: Mutex::new(Some(watcher)),
            cert_poller,
        })
    }

    /// Stop following the config: no more reloads (one under way finishes
    /// first), no more health checks. A node that is leaving calls it before
    /// it drains: applying a config then would make it listen again.
    /// Calling it again changes nothing.
    pub fn shutdown(&self) {
        self.reloader.tracked().following = false;
        self.watcher
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.cert_poller.abort();
        self.reloader.checker.stop_all();
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// What the reloads share, and what serializes them.
struct Tracked {
    /// The certificate files of the config last loaded, as they looked on
    /// disk then.
    cert_files: CertFiles,
    /// Whether changes are applied: from the first config until shutdown.
    following: bool,
}

/// Loads the dynamic config from disk and applies it. Shared by the config
/// file watcher and the certificate poller, which may fire at once.
struct Reloader {
    state: Arc<State>,
    listeners: Arc<Listeners<App>>,
    checker: Arc<HealthChecker>,
    config_file: PathBuf,
    cache_file: Option<PathBuf>,
    defaults: HealthCheckConfig,
    /// Holding the lock serializes reloads.
    tracked: Mutex<Tracked>,
}

impl Reloader {
    fn tracked(&self) -> MutexGuard<'_, Tracked> {
        // A reload that panicked leaves nothing half-updated in `Tracked`,
        // so later reloads may carry on.
        self.tracked.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Apply the config a starting node serves (see [`Controller::start`]),
    /// and start following changes.
    fn apply_initial(&self) -> Result<DynamicConfig, ReloadError> {
        let mut tracked = self.tracked();
        let control = &self.state.metrics().control;

        let deployed = load_dynamic_config(&self.config_file)
            .map_err(ReloadError::from)
            .and_then(|config| self.apply(&config, &mut tracked).map(|()| config));
        let unusable = match deployed {
            Ok(config) => {
                self.write_cache(&config);
                control.config_reload_failed.set(0);
                control.config_from_cache.set(0);
                tracked.following = true;
                return Ok(config);
            }
            Err(error) => error,
        };

        let Some(cache_file) = &self.cache_file else {
            return Err(unusable);
        };
        tracing::warn!(
            error = %unusable,
            cache = %cache_file.display(),
            "deployed dynamic config unusable, starting from the last-known-good cache"
        );
        let cached = load_dynamic_config(cache_file)
            .map_err(ReloadError::from)
            .and_then(|config| self.apply(&config, &mut tracked).map(|()| config))
            .map_err(|cache| ReloadError::NeitherUsable {
                deployed: Box::new(unusable),
                path: cache_file.clone(),
                cache: Box::new(cache),
            })?;
        control.config_reload_errors.inc();
        control.config_reload_failed.set(1);
        control.config_from_cache.set(1);
        tracked.following = true;
        Ok(cached)
    }

    /// Apply `config` and make its listeners the running set, all or
    /// nothing, remembering how its certificate files look on disk.
    ///
    /// The config is validated and built before any socket is touched, so a
    /// config that is invalid leaves the sockets inherited from a replaced
    /// node for the next config to use (typically the last-known-good
    /// cache). Only then are the sockets it adds bound, so a config whose
    /// listeners cannot be bound is rejected before anything is swapped.
    ///
    /// The certificate files are looked at before they are read, so a file
    /// replaced in between is seen as changed by the next poll.
    fn apply(&self, config: &DynamicConfig, tracked: &mut Tracked) -> Result<(), ReloadError> {
        tracked.cert_files = CertFiles::snapshot(&config.certificates);
        let prepared = prepare(config)?;
        let staged = self
            .listeners
            .stage(&config.listeners)
            .map_err(ReloadError::Bind)?;
        install(&self.state, prepared);
        self.listeners.commit(staged);
        Ok(())
    }

    fn write_cache(&self, config: &DynamicConfig) {
        if let Some(cache_file) = &self.cache_file
            && let Err(error) = cache::write(cache_file, config)
        {
            tracing::warn!(
                %error,
                cache = %cache_file.display(),
                "failed to write the last-known-good cache"
            );
        }
    }

    /// Reload because the dynamic config file changed.
    fn reload(&self) {
        let mut tracked = self.tracked();
        if tracked.following {
            self.reload_locked(&mut tracked);
        }
    }

    /// Reload if a certificate file of the current config changed on disk.
    fn reload_if_certificates_changed(&self) {
        let mut tracked = self.tracked();
        if !tracked.following || !tracked.cert_files.changed_on_disk() {
            return;
        }
        // Accept what is on disk now even if the reload below is rejected
        // (a rotation caught between the certificate and its key), so that a
        // broken state is reported once and not on every poll. The next
        // change of a file triggers the next attempt.
        tracked.cert_files.refresh();
        tracing::info!("certificate files changed on disk, reloading");
        self.reload_locked(&mut tracked);
    }

    /// Load the dynamic config from disk and apply it; on any failure the
    /// running config is kept.
    fn reload_locked(&self, tracked: &mut Tracked) {
        let control = &self.state.metrics().control;
        let applied = load_dynamic_config(&self.config_file)
            .map_err(ReloadError::from)
            .and_then(|config| self.apply(&config, tracked).map(|()| config));
        match applied {
            Ok(config) => {
                self.checker.reconcile(&config.pools, &self.defaults);
                self.write_cache(&config);
                control.config_reload_failed.set(0);
                control.config_from_cache.set(0);
                tracing::info!("hot-reloaded dynamic config");
            }
            Err(error) => {
                control.config_reload_errors.inc();
                control.config_reload_failed.set(1);
                tracing::warn!(%error, "dynamic config rejected, keeping the running one");
            }
        }
    }
}

#[cfg(test)]
#[path = "controller_test.rs"]
mod tests;
