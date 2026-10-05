//! What the tests of the binary share: scratch directories, free ports,
//! plain HTTP/1.1 requests, polling, and a node run as a service manager
//! runs it.

// Each test file uses its own part of this module.
#![allow(dead_code)]

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// How long a node may take to become ready, and how long a test waits for
/// anything else it polls for.
pub const PATIENCE: Duration = Duration::from_secs(20);

/// An empty directory of its own for `test` of the test file `file`.
pub fn scratch(file: &str, test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gfe-{file}-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A loopback address that was free a moment ago. Whoever uses it binds it
/// later, so another process may take it first: [`Node::start`] then
/// starts the node again on other ports.
pub fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// `GET path` on a new connection to `addr`; the whole response.
pub fn try_http_get(addr: SocketAddr, path: &str) -> io::Result<String> {
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

/// `GET path` on a new connection to `addr`; the whole response, or nothing
/// if nobody answers there.
pub fn http_get(addr: SocketAddr, path: &str) -> String {
    try_http_get(addr, path).unwrap_or_default()
}

/// Whether `condition` came true within [`PATIENCE`].
pub fn eventually(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// The dynamic config of a node that answers every request on its `http`
/// listener at `proxy` with a fixed `200 ok`.
pub fn fixed_response_config(proxy: SocketAddr) -> String {
    format!(
        r#"{{"listeners":[{{"id":"http","address":"{}","port":{},"protocol":"http"}}],
            "routes":[{{"id":"fixed","listener":"http","host":"*","path_prefix":"/",
                        "action":{{"fixed":{{"status":200,"body":"ok"}}}}}}]}}"#,
        proxy.ip(),
        proxy.port()
    )
}

/// Write to `dir` the bootstrap config of a node that serves its ops
/// endpoints on `ops`, whose dynamic config is `gfe-dynamic.json` and whose
/// last-known-good cache is `config-cache.json` there, followed by `extra`;
/// its path.
pub fn write_bootstrap(dir: &Path, ops: SocketAddr, extra: &str) -> PathBuf {
    write_bootstrap_with(dir, ops, "", extra)
}

/// [`write_bootstrap`], with `node_keys` added to its `[node]` section.
pub fn write_bootstrap_with(dir: &Path, ops: SocketAddr, node_keys: &str, extra: &str) -> PathBuf {
    let bootstrap = format!(
        "[node]\nid = \"t\"\nmetrics_addr = \"{ops}\"\n{node_keys}\n\
         [control_plane]\nconfig_file = \"{dir}/gfe-dynamic.json\"\n\
         local_cache = \"{dir}/config-cache.json\"\n\n[health_check_defaults]\n\n{extra}",
        dir = dir.display()
    );
    let path = dir.join("gfe.toml");
    std::fs::write(&path, bootstrap).unwrap();
    path
}

/// A running `gfe-node`, started as a service manager starts it, from the
/// files of its scratch directory. It leads a process group of its own, so
/// that it is stopped together with any successor it started when dropped.
pub struct Node {
    pub process: Child,
    /// Where its `http` listener is.
    pub proxy: SocketAddr,
    /// Where its ops endpoints are.
    pub ops: SocketAddr,
    pub dir: PathBuf,
    pub bootstrap: PathBuf,
}

/// How a test starts its node.
pub struct Launch<'a> {
    /// Lines added to the `[node]` section of the bootstrap config.
    pub node_keys: &'a str,
    /// What the bootstrap config ends with.
    pub extra: &'a str,
    /// The dynamic config, given the address of the `http` listener.
    pub dynamic: &'a dyn Fn(SocketAddr) -> String,
    /// Anything else about the command: its environment, its output.
    pub command: &'a dyn Fn(&mut Command),
}

impl Default for Launch<'_> {
    /// A node that answers every request with a fixed `200 ok`, with every
    /// default, its output discarded.
    fn default() -> Self {
        Launch {
            node_keys: "",
            extra: "",
            dynamic: &fixed_response_config,
            command: &|_| {},
        }
    }
}

impl Node {
    /// Start a node in `dir` as `launch` says and wait until it is ready.
    ///
    /// Its ports are chosen free just before it starts; if it cannot become
    /// ready (another process took a port first), it is started again on
    /// other ports, a few times.
    pub fn start(dir: &Path, launch: &Launch) -> Node {
        for _ in 0..3 {
            let mut node = Node::spawn(dir, launch);
            if node.wait_until_ready() {
                return node;
            }
            kill_group(&mut node.process);
        }
        panic!("the node in {} did not become ready", dir.display());
    }

    /// Start a node in `dir` as `launch` says, without waiting for anything.
    pub fn spawn(dir: &Path, launch: &Launch) -> Node {
        let (proxy, ops) = (free_addr(), free_addr());
        std::fs::write(dir.join("gfe-dynamic.json"), (launch.dynamic)(proxy)).unwrap();
        let bootstrap = write_bootstrap_with(dir, ops, launch.node_keys, launch.extra);
        let mut command = Command::new(env!("CARGO_BIN_EXE_gfe-node"));
        command
            .arg("--config")
            .arg(&bootstrap)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        (launch.command)(&mut command);
        Node {
            process: command.spawn().unwrap(),
            proxy,
            ops,
            dir: dir.to_path_buf(),
            bootstrap,
        }
    }

    /// Wait until the node says it is ready; whether it did before it
    /// exited or [`PATIENCE`] ran out.
    pub fn wait_until_ready(&mut self) -> bool {
        let deadline = Instant::now() + PATIENCE;
        while Instant::now() < deadline {
            if self.ops_get("/readyz").starts_with("HTTP/1.1 200") {
                return true;
            }
            if self.process.try_wait().unwrap().is_some() {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// The response of whichever process serves the ops endpoints now, or
    /// nothing if none does.
    pub fn ops_get(&self, path: &str) -> String {
        http_get(self.ops, path)
    }

    /// Send `signal` (as `kill` names it: `-TERM`) to the process the test
    /// started.
    pub fn signal(&self, signal: &str) {
        send_signal(signal, &self.process.id().to_string());
    }

    /// How the process the test started ended, if it did within
    /// [`PATIENCE`].
    pub fn exit(&mut self) -> Option<ExitStatus> {
        let mut status = None;
        eventually(|| {
            status = self.process.try_wait().unwrap();
            status.is_some()
        });
        status
    }

    /// Everything the node has written to its standard output, which the
    /// test must have piped, once the node has exited.
    pub fn output(&mut self) -> String {
        let mut output = String::new();
        self.process
            .stdout
            .take()
            .expect("the node's standard output is piped")
            .read_to_string(&mut output)
            .unwrap();
        output
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        kill_group(&mut self.process);
    }
}

/// Send `signal` to the process `pid`.
pub fn send_signal(signal: &str, pid: &str) {
    let sent = Command::new("kill").args([signal, pid]).status().unwrap();
    assert!(sent.success(), "kill {signal} {pid}");
}

/// Whether the process `pid` exists.
pub fn is_running(pid: &str) -> bool {
    Command::new("kill")
        .args(["-0", pid])
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
}

/// Kill every process of the group `leader` leads, and collect `leader`.
pub fn kill_group(leader: &mut Child) {
    let group = format!("-{}", leader.id());
    let _ = Command::new("kill")
        .args(["-KILL", "--", &group])
        .stderr(Stdio::null())
        .status();
    let _ = leader.wait();
}

/// The JSON log lines in `log` whose `target` is `target`.
pub fn events<'a>(log: &'a str, target: &str) -> Vec<&'a str> {
    let target = format!(r#""target":"{target}""#);
    log.lines().filter(|line| line.contains(&target)).collect()
}
