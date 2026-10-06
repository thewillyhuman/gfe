//! What the unit tests of the handler share: a node config to build a
//! [`State`] from.

use crate::handler::State;
use crate::metrics::GfeMetrics;
use gfe_config::{ControlPlaneConfig, NodeConfig, NodeSection};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A node config with every default.
pub(crate) fn node_config() -> NodeConfig {
    NodeConfig {
        node: NodeSection {
            id: "test".into(),
            loopback_vip: None,
            metrics_addr: "127.0.0.1:0".parse().unwrap(),
            worker_threads: 1,
        },
        control_plane: ControlPlaneConfig {
            config_file: "/nonexistent".into(),
            local_cache: None,
            reload_debounce: std::time::Duration::from_millis(250),
        },
        tls: Default::default(),
        limits: Default::default(),
        timeouts: Default::default(),
        upstream: Default::default(),
        ebpf: None,
        log: Default::default(),
        health_check_defaults: Default::default(),
    }
}

/// The state of a node configured by `config`.
pub(crate) fn state_with(config: &NodeConfig) -> Arc<State> {
    State::new(config, Arc::new(GfeMetrics::new())).unwrap()
}

/// The state of a node configured by [`node_config`].
pub(crate) fn state() -> Arc<State> {
    state_with(&node_config())
}

/// A file of its own holding `content`, in the temporary directory.
pub(crate) fn temp_file(content: &[u8]) -> PathBuf {
    // Tests run in parallel, each wants files of its own.
    static FILES: AtomicUsize = AtomicUsize::new(0);
    let n = FILES.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("gfe-handler-{}-{n}", std::process::id()));
    std::fs::write(&path, content).unwrap();
    path
}
