//! Starting `gfe-node`: when the deployed dynamic config cannot be used, and
//! with a bootstrap config that still sets keys that no longer do anything.
//! The binary is run as the service manager would run it.
#![cfg(unix)]

mod common;

use common::{Launch, Node, PATIENCE, eventually, free_addr, scratch, write_bootstrap};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Instant;

fn spawn_node(bootstrap: &std::path::Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_gfe-node"))
        .arg("--config")
        .arg(bootstrap)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

/// Whether something accepts connections on `addr` within [`PATIENCE`].
fn accepts_connections(addr: SocketAddr) -> bool {
    eventually(|| TcpStream::connect(addr).is_ok())
}

#[test]
fn serves_the_cached_config_when_the_dynamic_config_is_missing() {
    let dir = scratch("startup", "cached");
    let listener = free_addr();
    let cached = format!(
        r#"{{"listeners":[{{"id":"http","address":"{}","port":{},"protocol":"http"}}]}}"#,
        listener.ip(),
        listener.port()
    );
    std::fs::write(dir.join("config-cache.json"), cached).unwrap();
    let bootstrap = write_bootstrap(&dir, free_addr(), "");

    let mut node = spawn_node(&bootstrap);
    let serving = accepts_connections(listener);
    node.kill().unwrap();
    node.wait().unwrap();

    assert!(serving, "the node did not serve its cached config");
}

#[test]
fn exits_when_neither_dynamic_config_nor_cache_exists() {
    let dir = scratch("startup", "nothing");
    let bootstrap = write_bootstrap(&dir, free_addr(), "");

    let started = Instant::now();
    let status = spawn_node(&bootstrap).wait().unwrap();

    assert!(!status.success());
    assert!(started.elapsed() < PATIENCE, "{:?}", started.elapsed());
}

/// Keys a deployed bootstrap config may still set: the node starts, and
/// says in its log, once for each, that it ignores it.
#[test]
fn starts_with_deprecated_keys_and_warns_of_each() {
    let dir = scratch("startup", "deprecated");
    let mut node = Node::start(
        &dir,
        &Launch {
            node_keys: "loopback_vip = \"127.0.0.1\"\n",
            extra: "[ebpf]\nenabled = true\n\n[upstream]\nidle_per_host = 8\n",
            command: &|command| {
                command.stdout(Stdio::piped());
            },
            ..Launch::default()
        },
    );
    node.signal("-TERM");
    let output = node.output();
    assert!(node.exit().is_some_and(|status| status.success()));

    let warnings: Vec<&str> = output
        .lines()
        .filter(|line| line.contains(r#""level":"WARN""#))
        .collect();
    for key in ["[node] loopback_vip", "[ebpf]", "[upstream] idle_per_host"] {
        let about_it = warnings
            .iter()
            .filter(|line| line.contains(&format!("{key} is deprecated")))
            .count();
        assert_eq!(about_it, 1, "warnings about {key}: {warnings:#?}");
    }
}
