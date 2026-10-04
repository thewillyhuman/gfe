//! Starting `gfe-node` when the deployed dynamic config cannot be used: the
//! binary is run as the service manager would run it.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A scratch directory unique to one test.
fn scratch(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gfe-startup-{}-{test}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A loopback address that was free a moment ago.
fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// Write a bootstrap config for `dir`: the dynamic config is expected at
/// `gfe-dynamic.json` and the last-known-good cache at `config-cache.json`.
fn write_bootstrap(dir: &Path) -> PathBuf {
    let toml = format!(
        "[node]\nid = \"t\"\nloopback_vip = \"127.0.0.1\"\nmetrics_addr = \"{ops}\"\n\n\
         [control_plane]\nconfig_file = \"{dir}/gfe-dynamic.json\"\n\
         local_cache = \"{dir}/config-cache.json\"\n\n[health_check_defaults]\n",
        ops = free_addr(),
        dir = dir.display()
    );
    let path = dir.join("gfe.toml");
    std::fs::write(&path, toml).unwrap();
    path
}

fn spawn_node(bootstrap: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_gfe-node"))
        .arg("--config")
        .arg(bootstrap)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

/// Whether something accepts connections on `addr` within a few seconds.
fn accepts_connections(addr: SocketAddr) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn serves_the_cached_config_when_the_dynamic_config_is_missing() {
    let dir = scratch("cached");
    let listener = free_addr();
    let cached = format!(
        r#"{{"listeners":[{{"id":"http","address":"{}","port":{},"protocol":"http"}}]}}"#,
        listener.ip(),
        listener.port()
    );
    std::fs::write(dir.join("config-cache.json"), cached).unwrap();
    let bootstrap = write_bootstrap(&dir);

    let mut node = spawn_node(&bootstrap);
    let serving = accepts_connections(listener);
    node.kill().unwrap();
    node.wait().unwrap();

    assert!(serving, "the node did not serve its cached config");
}

#[test]
fn exits_when_neither_dynamic_config_nor_cache_exists() {
    let dir = scratch("nothing");
    let bootstrap = write_bootstrap(&dir);

    let status = spawn_node(&bootstrap).wait().unwrap();

    assert!(!status.success());
}
