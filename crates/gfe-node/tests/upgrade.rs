//! Replacing a running `gfe-node` in place: the binary is run as a node that
//! upgrades itself would run it.
#![cfg(unix)]

use gfe_handover::Sockets;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// A scratch directory unique to one test.
fn scratch(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gfe-upgrade-{}-{test}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Write to `dir` the config of a node that answers every request on `proxy`
/// with a fixed `200 ok` and serves its ops endpoints on `ops`; returns the
/// path of the bootstrap config. The node drains quickly, so that a test
/// does not wait long for one to stop.
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
         local_cache = \"{dir}/config-cache.json\"\n\n\
         [timeouts]\ndrain_deadline = \"1s\"\n\n[health_check_defaults]\n",
        dir = dir.display()
    );
    let path = dir.join("gfe.toml");
    std::fs::write(&path, bootstrap).unwrap();
    path
}

/// `GET path` on a new connection to `addr`; the whole response.
fn http_get(addr: SocketAddr, path: &str) -> String {
    try_http_get(addr, path).unwrap()
}

fn try_http_get(addr: SocketAddr, path: &str) -> io::Result<String> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
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

/// A loopback address that was free a moment ago.
fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
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

/// A node started the way a service manager starts it. It leads a process
/// group of its own, so that it is stopped together with any successor it
/// started when dropped.
struct Node {
    process: Child,
    proxy: SocketAddr,
    ops: SocketAddr,
    bootstrap: PathBuf,
}

impl Node {
    /// Start a node and wait until it is ready.
    fn start(test: &str) -> Node {
        let (proxy, ops) = (free_addr(), free_addr());
        let bootstrap = write_config(&scratch(test), proxy, ops);
        let process = Command::new(env!("CARGO_BIN_EXE_gfe-node"))
            .arg("--config")
            .arg(&bootstrap)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let node = Node {
            process,
            proxy,
            ops,
            bootstrap,
        };
        assert!(
            eventually(|| node.ops_get("/readyz").starts_with("HTTP/1.1 200")),
            "the node did not become ready"
        );
        node
    }

    /// The response of whichever process serves the ops endpoints now, or
    /// nothing if none does.
    fn ops_get(&self, path: &str) -> String {
        try_http_get(self.ops, path).unwrap_or_default()
    }

    /// Send `signal` to the process the test started.
    fn signal(&self, signal: &str) {
        let pid = self.process.id().to_string();
        let sent = Command::new("kill").args([signal, &pid]).status().unwrap();
        assert!(sent.success(), "kill {signal} {pid}");
    }

    /// How the process the test started ended, if it did within a while.
    fn exit(&mut self) -> Option<ExitStatus> {
        let mut status = None;
        eventually(|| {
            status = self.process.try_wait().unwrap();
            status.is_some()
        });
        status
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let group = format!("-{}", self.process.id());
        let _ = Command::new("kill")
            .args(["-KILL", "--", &group])
            .stderr(Stdio::null())
            .status();
        let _ = self.process.wait();
    }
}

/// Clients that keep sending requests to a node, one over a new connection
/// each time and one over a connection it keeps, until told to stop.
struct Load {
    stop: Arc<AtomicBool>,
    clients: Vec<JoinHandle<Outcome>>,
}

/// How many requests a client was answered, and what went wrong with the
/// others.
#[derive(Default)]
struct Outcome {
    answered: u64,
    failures: Vec<String>,
}

impl Load {
    fn start(proxy: SocketAddr) -> Load {
        let stop = Arc::new(AtomicBool::new(false));
        let clients = vec![
            std::thread::spawn({
                let stop = stop.clone();
                move || connect_for_each_request(proxy, &stop)
            }),
            std::thread::spawn({
                let stop = stop.clone();
                move || reuse_a_connection(proxy, &stop)
            }),
        ];
        Load { stop, clients }
    }

    /// Stop the clients; what they saw, together.
    fn finish(self) -> Outcome {
        self.stop.store(true, Ordering::SeqCst);
        let mut total = Outcome::default();
        for client in self.clients {
            let outcome = client.join().unwrap();
            total.answered += outcome.answered;
            total.failures.extend(outcome.failures);
        }
        total
    }
}

/// A pause between requests, so that a test does not use up the loopback
/// ports of the host.
const BETWEEN_REQUESTS: Duration = Duration::from_millis(2);

fn connect_for_each_request(proxy: SocketAddr, stop: &AtomicBool) -> Outcome {
    let mut outcome = Outcome::default();
    while !stop.load(Ordering::SeqCst) {
        match try_http_get(proxy, "/") {
            Ok(response) if response.starts_with("HTTP/1.1 200") => outcome.answered += 1,
            Ok(response) => outcome
                .failures
                .push(format!("new connection: {response:?}")),
            Err(e) => outcome.failures.push(format!("new connection: {e}")),
        }
        std::thread::sleep(BETWEEN_REQUESTS);
    }
    outcome
}

/// Behaves as an HTTP/1.1 client does: keeps its connection for the next
/// request, unless the response says `Connection: close`.
fn reuse_a_connection(proxy: SocketAddr, stop: &AtomicBool) -> Outcome {
    let mut outcome = Outcome::default();
    while !stop.load(Ordering::SeqCst) {
        let mut stream = match TcpStream::connect(proxy) {
            Ok(stream) => stream,
            Err(e) => {
                outcome.failures.push(format!("reconnecting: {e}"));
                continue;
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        while !stop.load(Ordering::SeqCst) {
            match request_on(&mut stream) {
                Ok(response) => {
                    outcome.answered += 1;
                    if response.to_ascii_lowercase().contains("connection: close") {
                        break;
                    }
                }
                Err(e) => {
                    outcome.failures.push(format!("kept connection: {e}"));
                    break;
                }
            }
            std::thread::sleep(BETWEEN_REQUESTS);
        }
    }
    outcome
}

/// One request on a connection that may be used again; its response.
fn request_on(stream: &mut TcpStream) -> io::Result<String> {
    stream.write_all(b"GET / HTTP/1.1\r\nhost: t\r\n\r\n")?;
    let mut response = Vec::new();
    let mut chunk = [0u8; 1024];
    while !response.ends_with(b"\r\n\r\nok") {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "closed before the response was complete",
            ));
        }
        response.extend_from_slice(&chunk[..read]);
    }
    Ok(String::from_utf8_lossy(&response).to_string())
}

#[test]
fn upgrades_in_place_without_failing_a_request() {
    let mut node = Node::start("in-place");
    let load = Load::start(node.proxy);
    // Some requests are served by the node, some while it is replaced, and
    // some by its successor.
    std::thread::sleep(Duration::from_millis(300));

    node.signal("-USR2");
    let old = node.exit();
    std::thread::sleep(Duration::from_millis(300));
    let outcome = load.finish();

    assert!(
        old.is_some_and(|status| status.success()),
        "the replaced node did not stop: {old:?}"
    );
    assert!(
        outcome.failures.is_empty(),
        "{} requests failed, {} were answered: {:?}",
        outcome.failures.len(),
        outcome.answered,
        outcome.failures
    );
    assert!(node.ops_get("/readyz").starts_with("HTTP/1.1 200"));
}

#[test]
fn keeps_serving_when_its_successor_cannot_start() {
    let mut node = Node::start("no-successor");
    std::fs::write(&node.bootstrap, "not a config").unwrap();

    node.signal("-USR2");
    let counted = eventually(|| {
        node.ops_get("/metrics")
            .contains("gfe_upgrade_failures_total 1")
    });

    assert!(counted, "the failed upgrade was not counted");
    assert_eq!(node.process.try_wait().unwrap(), None);
    assert!(http_get(node.proxy, "/").starts_with("HTTP/1.1 200"));
}
