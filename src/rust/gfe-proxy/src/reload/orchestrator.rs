//! The control-plane orchestrator: ties together config load/apply, listener
//! reconciliation, the health checker, the last-known-good cache, the
//! hot-reload watcher, and the certificate file poller.

use crate::reload::{cache, install, prepare, spawn_watcher, CertFiles};
use crate::{ListenerSet, ProxyShared};
use gfe_core::config::{load_dynamic_config, DynamicConfig, HealthCheckConfig, NodeConfig};
use gfe_core::GfeError;
use gfe_health_checking::HealthChecker;
use notify::RecommendedWatcher;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::task::JoinHandle;

/// How often the certificate files are checked for a rotation. Certificates
/// are replaced in place without the dynamic config changing, so the config
/// watcher alone would never notice.
const CERT_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Orchestrates control-plane lifecycle for one node.
pub struct Controller {
    reloader: Arc<Reloader>,
    debounce: Duration,
    cert_poll_interval: Duration,
    // Kept alive for the lifetime of the controller so watching continues.
    _watcher: Option<RecommendedWatcher>,
    cert_poller: Option<JoinHandle<()>>,
}

impl Controller {
    /// A controller applying configs to `shared` and reconciling `listeners`.
    pub fn new(shared: Arc<ProxyShared>, listeners: Arc<ListenerSet>, node: &NodeConfig) -> Self {
        let checker = HealthChecker::new(shared.health.clone(), shared.server.metrics.clone());
        Controller {
            reloader: Arc::new(Reloader {
                shared,
                listeners,
                checker,
                config_file: node.control_plane.config_file.clone(),
                cache_file: node.control_plane.local_cache.clone(),
                defaults: node.health_check_defaults.clone(),
                cert_files: Mutex::new(CertFiles::default()),
            }),
            debounce: node.control_plane.reload_debounce,
            cert_poll_interval: CERT_POLL_INTERVAL,
            _watcher: None,
            cert_poller: None,
        }
    }

    /// Check the certificate files for a rotation every `interval` instead of
    /// the default 10 seconds.
    pub fn cert_poll_interval(mut self, interval: Duration) -> Self {
        self.cert_poll_interval = interval;
        self
    }

    /// Apply the initial config and bind its listeners, start health probes,
    /// and begin watching for changes to the dynamic config and to the
    /// certificate files it names.
    ///
    /// The initial config is the deployed dynamic config or, if that cannot
    /// be used, the last-known-good cache. Fails, with nothing serving, if
    /// neither can be applied. Must be called from within a Tokio runtime.
    pub fn start(&mut self) -> Result<(), GfeError> {
        let cfg = self.reloader.apply_initial()?;
        self.reloader
            .checker
            .reconcile(&cfg.pools, &self.reloader.defaults);

        let reloader = self.reloader.clone();
        let watcher = spawn_watcher(
            &self.reloader.config_file,
            self.debounce,
            Arc::new(move || reloader.reload()),
        )?;
        self._watcher = Some(watcher);
        tracing::info!(
            file = %self.reloader.config_file.display(),
            "watching dynamic config for changes"
        );

        let reloader = self.reloader.clone();
        // The files were read just now, so the first check is one interval out.
        let first_check = tokio::time::Instant::now() + self.cert_poll_interval;
        let mut ticker = tokio::time::interval_at(first_check, self.cert_poll_interval);
        self.cert_poller = Some(tokio::spawn(async move {
            loop {
                ticker.tick().await;
                reloader.reload_if_certs_changed();
            }
        }));
        Ok(())
    }

    /// Stop all health probes and the certificate poller.
    pub fn shutdown(&self) {
        self.reloader.checker.stop_all();
        if let Some(poller) = &self.cert_poller {
            poller.abort();
        }
    }
}

/// Loads the dynamic config from disk and applies it. Shared by the config
/// file watcher and the certificate poller, which may fire concurrently.
struct Reloader {
    shared: Arc<ProxyShared>,
    listeners: Arc<ListenerSet>,
    checker: Arc<HealthChecker>,
    config_file: PathBuf,
    cache_file: Option<PathBuf>,
    defaults: HealthCheckConfig,
    /// The certificate files of the config last loaded, as they looked on
    /// disk then. Holding the lock also serializes reloads.
    cert_files: Mutex<CertFiles>,
}

impl Reloader {
    fn lock_cert_files(&self) -> MutexGuard<'_, CertFiles> {
        // A reload that panicked leaves nothing half-updated in `CertFiles`,
        // so later reloads may carry on.
        self.cert_files
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Apply the config a starting node serves: the deployed dynamic config
    /// or, if that cannot be loaded, is invalid or cannot be applied, the
    /// last-known-good cache. A node that restarts while its config is
    /// missing or broken thus keeps serving what it served before, exactly as
    /// a running node does when it rejects a reload.
    fn apply_initial(&self) -> Result<DynamicConfig, GfeError> {
        let mut cert_files = self.lock_cert_files();

        let deployed = load_dynamic_config(&self.config_file)
            .and_then(|cfg| self.apply_tracked(&cfg, &mut cert_files).map(|()| cfg));
        let unusable = match deployed {
            Ok(cfg) => {
                self.write_cache(&cfg);
                self.shared
                    .server
                    .metrics
                    .control
                    .config_reload_failed
                    .set(0);
                return Ok(cfg);
            }
            Err(e) => e,
        };

        let Some(cache) = &self.cache_file else {
            return Err(unusable);
        };
        tracing::warn!(
            error = %unusable,
            cache = %cache.display(),
            "deployed dynamic config unusable, starting from the last-known-good cache"
        );
        let cached = cache::read(cache)
            .and_then(|cfg| self.apply_tracked(&cfg, &mut cert_files).map(|()| cfg))
            .map_err(|cache_error| {
                GfeError::Config(format!(
                    "{unusable}; and the last-known-good cache is unusable too: {cache_error}"
                ))
            })?;
        self.shared
            .server
            .metrics
            .control
            .config_reload_errors
            .inc();
        self.shared
            .server
            .metrics
            .control
            .config_reload_failed
            .set(1);
        self.shared.server.metrics.control.config_from_cache.set(1);
        Ok(cached)
    }

    /// Apply `cfg` with its listeners, remembering how its certificate files
    /// look on disk. The snapshot is taken before the files are read, so a
    /// file replaced in between is seen as changed by the next poll.
    fn apply_tracked(
        &self,
        cfg: &DynamicConfig,
        cert_files: &mut CertFiles,
    ) -> Result<(), GfeError> {
        *cert_files = CertFiles::snapshot(&cfg.certificates);
        self.apply_with_listeners(cfg)
    }

    /// Apply `cfg` and make its listeners the running set, all or nothing.
    ///
    /// The config is validated and built before any socket is touched, so a
    /// config that is invalid leaves the sockets inherited from a replaced
    /// node for the next config to use (typically the last-known-good
    /// cache). Only then are the sockets it adds bound, so a config whose
    /// listeners cannot be bound is rejected before anything is swapped.
    fn apply_with_listeners(&self, cfg: &DynamicConfig) -> Result<(), GfeError> {
        let prepared = prepare(cfg)?;
        let staged = self
            .listeners
            .stage(&cfg.listeners)
            .map_err(|e| GfeError::Config(e.to_string()))?;
        install(&self.shared, prepared);
        self.listeners.commit(staged);
        Ok(())
    }

    fn write_cache(&self, cfg: &DynamicConfig) {
        if let Some(cache) = &self.cache_file {
            if let Err(e) = cache::write(cache, cfg) {
                tracing::warn!(error = %e, "failed to write config cache");
            }
        }
    }

    /// Reload because the dynamic config file changed.
    fn reload(&self) {
        let mut cert_files = self.lock_cert_files();
        self.reload_locked(&mut cert_files);
    }

    /// Reload if a certificate file of the current config changed on disk.
    fn reload_if_certs_changed(&self) {
        let mut cert_files = self.lock_cert_files();
        if !cert_files.changed_on_disk() {
            return;
        }
        // Accept what is on disk now even if the reload below is rejected
        // (e.g. a rotation caught between the certificate and its key), so
        // that a broken state is reported once and not on every poll. The
        // next file change triggers the next attempt.
        cert_files.refresh();
        tracing::info!("certificate files changed on disk, reloading");
        self.reload_locked(&mut cert_files);
    }

    /// Load the dynamic config from disk and apply it; on any failure the
    /// running config is kept.
    fn reload_locked(&self, cert_files: &mut CertFiles) {
        let cfg = match load_dynamic_config(&self.config_file) {
            Ok(c) => c,
            Err(e) => {
                self.shared
                    .server
                    .metrics
                    .control
                    .config_reload_errors
                    .inc();
                self.shared
                    .server
                    .metrics
                    .control
                    .config_reload_failed
                    .set(1);
                tracing::warn!(error = %e, "config reload failed to load; keeping current");
                return;
            }
        };
        match self.apply_tracked(&cfg, cert_files) {
            Ok(()) => {
                self.checker.reconcile(&cfg.pools, &self.defaults);
                self.write_cache(&cfg);
                self.shared
                    .server
                    .metrics
                    .control
                    .config_reload_failed
                    .set(0);
                self.shared.server.metrics.control.config_from_cache.set(0);
                tracing::info!("hot-reloaded dynamic config");
            }
            Err(e) => {
                self.shared
                    .server
                    .metrics
                    .control
                    .config_reload_errors
                    .inc();
                self.shared
                    .server
                    .metrics
                    .control
                    .config_reload_failed
                    .set(1);
                tracing::warn!(error = %e, "config reload rejected; keeping current");
            }
        }
    }
}
