//! Where `gfe-node` writes its log: the binary is run as the service manager
//! would run it.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A scratch directory unique to one test.
fn scratch(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gfe-logging-{}-{test}", std::process::id()));
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

/// `GET path` on a new connection to `addr`; the whole response, or nothing
/// if nobody answers there.
fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut response = String::new();
    if let Ok(mut stream) = TcpStream::connect(addr) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = write!(
            stream,
            "GET {path} HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n"
        );
        let _ = stream.read_to_string(&mut response);
    }
    response
}

/// Whether `condition` came true within a while.
fn eventually(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// A running node that answers every request with a fixed `200 ok`. Killed
/// when dropped.
struct Node {
    process: Child,
    proxy: SocketAddr,
    ops: SocketAddr,
}

impl Node {
    /// Start a node whose bootstrap config ends with `extra`, and wait until
    /// it is ready.
    fn start(dir: &Path, extra: &str) -> Node {
        let (proxy, ops) = (free_addr(), free_addr());
        let dynamic = format!(
            r#"{{"listeners":[{{"id":"http","address":"{}","port":{},"protocol":"http"}}],
                "routes":[{{"id":"fixed","listener":"http","host":"*","path_prefix":"/",
                            "action":{{"fixed":{{"status":200,"body":"ok"}}}}}}]}}"#,
            proxy.ip(),
            proxy.port()
        );
        std::fs::write(dir.join("gfe-dynamic.json"), dynamic).unwrap();
        let bootstrap = format!(
            "[node]\nid = \"t\"\nloopback_vip = \"127.0.0.1\"\nmetrics_addr = \"{ops}\"\n\n\
             [control_plane]\nconfig_file = \"{dir}/gfe-dynamic.json\"\n\
             local_cache = \"{dir}/config-cache.json\"\n\n[health_check_defaults]\n\n{extra}",
            dir = dir.display()
        );
        std::fs::write(dir.join("gfe.toml"), bootstrap).unwrap();
        let process = Command::new(env!("CARGO_BIN_EXE_gfe-node"))
            .arg("--config")
            .arg(dir.join("gfe.toml"))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let node = Node {
            process,
            proxy,
            ops,
        };
        assert!(
            eventually(|| http_get(node.ops, "/readyz").starts_with("HTTP/1.1 200")),
            "the node did not become ready"
        );
        node
    }
}

impl Node {
    /// Stop the node as a service manager does, and return everything it
    /// wrote to standard output.
    #[cfg(unix)]
    fn stop(mut self) -> String {
        let pid = self.process.id().to_string();
        Command::new("kill").arg(&pid).status().unwrap();
        let mut output = String::new();
        self.process
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut output)
            .unwrap();
        output
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

#[test]
fn reports_how_many_log_lines_were_lost_per_destination() {
    let node = Node::start(&scratch("lost"), "");
    http_get(node.proxy, "/");

    let metrics = http_get(node.ops, "/metrics");

    assert!(
        metrics.contains(r#"gfe_log_lost_lines{destination="stdout"} 0"#),
        "{metrics}"
    );
}

#[cfg(unix)]
#[test]
fn writes_out_its_last_lines_before_it_exits() {
    let node = Node::start(&scratch("last-lines"), "");

    let output = node.stop();

    let last = output.lines().last().unwrap_or_default();
    assert!(last.contains("gfe-node stopped"), "{output}");
}
