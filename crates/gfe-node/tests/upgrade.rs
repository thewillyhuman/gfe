//! Replacing a running `gfe-node` in place: the binary is run as a node that
//! upgrades itself would run it.
#![cfg(unix)]

use gfe_handover::Sockets;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// A scratch directory unique to one test.
fn scratch(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gfe-upgrade-{}-{test}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Write to `dir` the config of a node that answers every request on `proxy`
/// with a fixed `200 ok` and serves its ops endpoints on `ops`; returns the
/// path of the bootstrap config.
fn write_config(dir: &Path, proxy: SocketAddr, ops: SocketAddr) -> PathBuf {
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
         local_cache = \"{dir}/config-cache.json\"\n\n[health_check_defaults]\n",
        dir = dir.display()
    );
    let path = dir.join("gfe.toml");
    std::fs::write(&path, bootstrap).unwrap();
    path
}

/// `GET path` on a new connection to `addr`; the whole response.
fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

/// A node that was started to take over the sockets of this test, which
/// plays the node being replaced. Stopped when dropped.
struct Successor {
    node: Child,
    proxy: SocketAddr,
    ops: SocketAddr,
    /// The outgoing node's copies of the sockets. Never accepted on, so
    /// whatever answers on these addresses is the successor.
    _sockets: Sockets,
}

impl Successor {
    /// Start a node with `--upgrade`, hand it a proxy and an ops socket, and
    /// wait until it says it accepts connections.
    fn start(test: &str) -> Successor {
        let proxy_socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let ops_socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = proxy_socket.local_addr().unwrap();
        let ops = ops_socket.local_addr().unwrap();
        let bootstrap = write_config(&scratch(test), proxy, ops);
        let sockets = Sockets {
            listeners: vec![(proxy, proxy_socket)],
            ops: Some((ops, ops_socket)),
        };

        let (ours, theirs) = UnixStream::pair().unwrap();
        let node = Command::new(env!("CARGO_BIN_EXE_gfe-node"))
            .arg("--config")
            .arg(bootstrap)
            .arg("--upgrade")
            .stdin(Stdio::from(OwnedFd::from(theirs)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        gfe_handover::send(&ours, &sockets).unwrap();
        ours.set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        gfe_handover::await_confirmation(&ours).expect("the node should take over");

        Successor {
            node,
            proxy,
            ops,
            _sockets: sockets,
        }
    }
}

impl Drop for Successor {
    fn drop(&mut self) {
        let _ = self.node.kill();
        let _ = self.node.wait();
    }
}

#[test]
fn serves_on_the_listening_socket_it_takes_over() {
    let successor = Successor::start("proxy");

    let response = http_get(successor.proxy, "/");

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("ok"), "{response}");
}

#[test]
fn serves_its_ops_endpoints_on_the_socket_it_takes_over() {
    let successor = Successor::start("ops");

    let response = http_get(successor.ops, "/readyz");

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}
