//! What the unit tests of the proxy share: a node config to build a
//! [`State`] from.

use crate::listener::Connections;
use crate::proxy::State;
use gfe_config::{ControlPlaneConfig, NodeConfig, NodeSection};
use netkit_observability::GfeMetrics;
use std::sync::Arc;

/// A node config with every default, and two worker threads.
pub(crate) fn node_config() -> NodeConfig {
    NodeConfig {
        node: NodeSection {
            id: "test".into(),
            loopback_vip: None,
            metrics_addr: "127.0.0.1:0".parse().unwrap(),
            worker_threads: 2,
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

/// The state of a node configured by [`node_config`].
pub(crate) fn state() -> Arc<State> {
    State::new(
        &node_config(),
        Arc::new(GfeMetrics::new()),
        Connections::new(),
        tokio::sync::watch::channel(false).1,
    )
    .unwrap()
}
