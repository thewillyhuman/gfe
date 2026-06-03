//! The control-plane orchestrator: ties together config load/apply, the
//! health checker, the last-known-good cache, and the hot-reload watcher.

use gfe_config::{apply, cache, load_dynamic_config, spawn_watcher, validate};
use gfe_health::HealthChecker;
use gfe_proxy::ProxyShared;
use gfe_types::{DynamicConfig, GfeError, HealthCheckConfig, NodeConfig};
use notify::RecommendedWatcher;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Orchestrates control-plane lifecycle for one node.
pub struct Controller {
    shared: Arc<ProxyShared>,
    checker: Arc<HealthChecker>,
    config_file: PathBuf,
    cache_file: Option<PathBuf>,
    defaults: HealthCheckConfig,
    debounce: Duration,
    // Kept alive for the lifetime of the controller so watching continues.
    _watcher: Option<RecommendedWatcher>,
}

impl Controller {
    pub fn new(shared: Arc<ProxyShared>, node: &NodeConfig) -> Self {
        let checker = HealthChecker::new(shared.health.clone(), shared.metrics.clone());
        Controller {
            shared,
            checker,
            config_file: node.control_plane.config_file.clone(),
            cache_file: node.control_plane.local_cache.clone(),
            defaults: node.health_check_defaults.clone(),
            debounce: node.control_plane.reload_debounce,
            _watcher: None,
        }
    }

    /// Load and apply the initial config (with cache fallback), start health
    /// probes, write the cache, and begin watching for changes.
    ///
    /// Returns the initial dynamic config so the caller can bind listeners.
    /// Must be called from within a Tokio runtime.
    pub fn start(&mut self) -> Result<DynamicConfig, GfeError> {
        let cfg = self.load_initial()?;
        apply(&self.shared, &cfg)?;
        self.checker.reconcile(&cfg.pools, &self.defaults);
        self.write_cache(&cfg);

        let reload = self.make_reload();
        let watcher = spawn_watcher(&self.config_file, self.debounce, reload)?;
        self._watcher = Some(watcher);
        tracing::info!(file = %self.config_file.display(), "watching dynamic config for changes");
        Ok(cfg)
    }

    /// Stop all health probes.
    pub fn shutdown(&self) {
        self.checker.stop_all();
    }

    fn load_initial(&self) -> Result<DynamicConfig, GfeError> {
        match load_dynamic_config(&self.config_file) {
            Ok(cfg) => {
                validate(&cfg)?;
                Ok(cfg)
            }
            Err(e) => {
                if let Some(cache) = &self.cache_file {
                    tracing::warn!(
                        error = %e,
                        cache = %cache.display(),
                        "config unavailable, falling back to cached config"
                    );
                    let cfg = cache::read(cache)?;
                    validate(&cfg)?;
                    Ok(cfg)
                } else {
                    Err(e)
                }
            }
        }
    }

    fn write_cache(&self, cfg: &DynamicConfig) {
        if let Some(cache) = &self.cache_file {
            if let Err(e) = cache::write(cache, cfg) {
                tracing::warn!(error = %e, "failed to write config cache");
            }
        }
    }

    /// Build the debounced reload closure run by the watcher.
    fn make_reload(&self) -> Arc<dyn Fn() + Send + Sync> {
        let shared = self.shared.clone();
        let checker = self.checker.clone();
        let config_file = self.config_file.clone();
        let cache_file = self.cache_file.clone();
        let defaults = self.defaults.clone();

        Arc::new(move || {
            let cfg = match load_dynamic_config(&config_file) {
                Ok(c) => c,
                Err(e) => {
                    shared.metrics.control.config_reload_errors.inc();
                    tracing::warn!(error = %e, "config reload failed to load; keeping current");
                    return;
                }
            };
            match apply(&shared, &cfg) {
                Ok(()) => {
                    checker.reconcile(&cfg.pools, &defaults);
                    if let Some(cache) = &cache_file {
                        if let Err(e) = cache::write(cache, &cfg) {
                            tracing::warn!(error = %e, "failed to write config cache");
                        }
                    }
                    tracing::info!("hot-reloaded dynamic config");
                }
                Err(e) => {
                    shared.metrics.control.config_reload_errors.inc();
                    tracing::warn!(error = %e, "config reload rejected; keeping current");
                }
            }
        })
    }
}
