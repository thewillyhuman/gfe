//! Replacing a running `gfe-node` in place: the binary is run as a node that
//! upgrades itself would run it.
#![cfg(unix)]

mod common;

use common::{
    Launch, Node, PATIENCE, eventually, fixed_response_config, http_get, is_running, kill_group,
    scratch, send_signal, try_http_get, write_bootstrap,
};
use gfe_node::handover::Sockets;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The `[timeouts]` section of a node that stops within `drain_deadline`.
fn draining_for(drain_deadline: &str) -> String {
    format!("[timeouts]\ndrain_deadline = \"{drain_deadline}\"\n")
}

/// A node that was started to take over the sockets of this test, which
/// plays the node being replaced. Stopped when dropped.
struct Successor {
    /// What the test started, which starts the successor and exits. It
    /// leads a process group that the successor is in, too.
    launcher: Child,
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
        let dir = scratch("up", test);
        std::fs::write(dir.join("gfe-dynamic.json"), fixed_response_config(proxy)).unwrap();
        let bootstrap = write_bootstrap(&dir, ops, &draining_for("1s"));
        let sockets = Sockets {
            listeners: vec![(proxy, proxy_socket)],
            ops: Some((ops, ops_socket)),
        };

        let (ours, theirs) = UnixStream::pair().unwrap();
        let launcher = Command::new(env!("CARGO_BIN_EXE_gfe-node"))
            .arg("--config")
            .arg(bootstrap)
            .arg("--upgrade")
            .stdin(Stdio::from(OwnedFd::from(theirs)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        gfe_node::handover::send(&ours, &sockets).unwrap();
        let deadline = Instant::now() + PATIENCE;
        gfe_node::handover::await_receipt(&ours, deadline)
            .expect("the node should take the sockets");
        gfe_node::handover::await_confirmation(&ours, deadline).expect("the node should take over");

        Successor {
            launcher,
            proxy,
            ops,
            _sockets: sockets,
        }
    }
}

impl Drop for Successor {
    fn drop(&mut self) {
        kill_group(&mut self.launcher);
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

/// A node started the way a service manager starts it, which listens to
/// what the node tells it.
struct Managed {
    node: Node,
    /// Where the node sends what it tells the service manager.
    service_manager: UnixDatagram,
}

impl std::ops::Deref for Managed {
    type Target = Node;

    fn deref(&self) -> &Node {
        &self.node
    }
}

impl std::ops::DerefMut for Managed {
    fn deref_mut(&mut self) -> &mut Node {
        &mut self.node
    }
}

impl Managed {
    /// Start a node that drains quickly, so that a test does not wait long
    /// for it to stop, and wait until it is ready.
    fn start(test: &str) -> Managed {
        Managed::start_draining_for(test, "1s")
    }

    /// Start a node with the given `drain_deadline` and wait until it is
    /// ready.
    ///
    /// Like [`Node::start`], it starts the node again on other ports if it
    /// cannot become ready. Each attempt is given a service manager of its
    /// own: one given up on may still have said it was ready, and the test
    /// would take that for what the node it keeps says.
    fn start_draining_for(test: &str, drain_deadline: &str) -> Managed {
        let dir = scratch("up", test);
        let extra = draining_for(drain_deadline);
        for attempt in 0..3 {
            let notify_socket = dir.join(format!("notify-{attempt}"));
            let service_manager = UnixDatagram::bind(&notify_socket).unwrap();
            service_manager.set_read_timeout(Some(PATIENCE)).unwrap();
            let mut node = Node::spawn(
                &dir,
                &Launch {
                    extra: &extra,
                    command: &|command| {
                        command.env("NOTIFY_SOCKET", &notify_socket);
                    },
                    ..Launch::default()
                },
            );
            if node.wait_until_ready() {
                return Managed {
                    node,
                    service_manager,
                };
            }
            kill_group(&mut node.process);
        }
        panic!("the node in {} did not become ready", dir.display());
    }

    /// The process id the node announces as the service's main process
    /// once its successor has taken over, after it has said it upgrades.
    fn announced_successor(&self) -> String {
        assert_eq!(self.tells_service_manager(), ["RELOADING=1"]);
        let announced = self.tells_service_manager();
        announced
            .iter()
            .find_map(|line| line.strip_prefix("MAINPID="))
            .unwrap_or_else(|| panic!("no MAINPID in {announced:?}"))
            .to_string()
    }

    /// The next thing the node tells the service manager, as `KEY=value`
    /// lines.
    fn tells_service_manager(&self) -> Vec<String> {
        let mut message = [0u8; 1024];
        let length = self
            .service_manager
            .recv(&mut message)
            .expect("the node should have told the service manager something");
        String::from_utf8_lossy(&message[..length])
            .lines()
            .map(str::to_string)
            .collect()
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

impl Load {
    /// Probe `/readyz` at `ops` as load balancers do: one prober over a new
    /// connection each time, one over a connection it keeps until it is
    /// closed.
    fn probe_readiness(ops: SocketAddr) -> Load {
        let stop = Arc::new(AtomicBool::new(false));
        let clients = vec![
            std::thread::spawn({
                let stop = stop.clone();
                move || probe_with_a_connection_each(ops, &stop)
            }),
            std::thread::spawn({
                let stop = stop.clone();
                move || probe_over_a_kept_connection(ops, &stop)
            }),
        ];
        Load { stop, clients }
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

/// Whether `response` says the node is ready.
fn says_ready(response: &str) -> bool {
    response.starts_with("HTTP/1.1 200")
}

fn probe_with_a_connection_each(ops: SocketAddr, stop: &AtomicBool) -> Outcome {
    let mut outcome = Outcome::default();
    while !stop.load(Ordering::SeqCst) {
        match try_http_get(ops, "/readyz") {
            Ok(response) if says_ready(&response) => outcome.answered += 1,
            Ok(response) => outcome
                .failures
                .push(format!("new connection: {response:?}")),
            Err(e) => outcome.failures.push(format!("new connection: {e}")),
        }
        std::thread::sleep(BETWEEN_REQUESTS);
    }
    outcome
}

/// Keeps its connection for the next probe until the server closes it. A
/// probe that finds its kept connection closed before any answer arrives is
/// sent again over a new one, as HTTP/1.1 clients do with a request that
/// changes nothing (RFC 9112, section 9.3.1).
fn probe_over_a_kept_connection(ops: SocketAddr, stop: &AtomicBool) -> Outcome {
    let mut outcome = Outcome::default();
    let mut kept: Option<TcpStream> = None;
    while !stop.load(Ordering::SeqCst) {
        let reused = kept.is_some();
        let mut stream = match kept.take() {
            Some(stream) => stream,
            None => match TcpStream::connect(ops) {
                Ok(stream) => stream,
                Err(e) => {
                    outcome.failures.push(format!("reconnecting: {e}"));
                    continue;
                }
            },
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        match probe_on(&mut stream) {
            Ok(Some(response)) => {
                if says_ready(&response) {
                    outcome.answered += 1;
                } else {
                    outcome
                        .failures
                        .push(format!("kept connection: {response:?}"));
                }
                if !response.to_ascii_lowercase().contains("connection: close") {
                    kept = Some(stream);
                }
            }
            Ok(None) if reused => continue,
            Ok(None) => outcome
                .failures
                .push("new connection closed without an answer".to_string()),
            Err(e) => outcome.failures.push(format!("kept connection: {e}")),
        }
        std::thread::sleep(BETWEEN_REQUESTS);
    }
    outcome
}

/// One `GET /readyz` on a connection that may be used again: its response,
/// or `None` if the connection was closed before any of it arrived.
fn probe_on(stream: &mut TcpStream) -> io::Result<Option<String>> {
    fn closed(e: &io::Error) -> bool {
        use io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset};
        matches!(e.kind(), BrokenPipe | ConnectionAborted | ConnectionReset)
    }

    match stream.write_all(b"GET /readyz HTTP/1.1\r\nhost: t\r\n\r\n") {
        Err(e) if closed(&e) => return Ok(None),
        sent => sent?,
    }
    let mut response = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = match stream.read(&mut chunk) {
            Ok(0) if response.is_empty() => return Ok(None),
            Err(e) if response.is_empty() && closed(&e) => return Ok(None),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "closed before the response was complete",
                ));
            }
            Ok(read) => read,
            Err(e) => return Err(e),
        };
        response.extend_from_slice(&chunk[..read]);
        let text = String::from_utf8_lossy(&response).to_string();
        if let Some((head, body)) = text.split_once("\r\n\r\n")
            && body.len() >= content_length(head)
        {
            return Ok(Some(text));
        }
    }
}

/// The `Content-Length` of a response whose head is `head`; 0 if it has
/// none.
fn content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0)
}

#[test]
fn readiness_probes_see_the_node_ready_throughout_an_upgrade() {
    let mut node = Managed::start_draining_for("readiness", "8s");
    node.tells_service_manager();
    // Keeps the outgoing node around while it drains, so that it could
    // still answer probes after the successor has taken over.
    let mut client = TcpStream::connect(node.proxy).unwrap();
    request_on(&mut client).unwrap();
    let probes = Load::probe_readiness(node.ops);
    std::thread::sleep(Duration::from_millis(300));

    node.signal("-USR2");
    node.tells_service_manager();
    node.tells_service_manager();
    std::thread::sleep(Duration::from_millis(1000));
    let outcome = probes.finish();

    assert_eq!(
        node.process.try_wait().unwrap(),
        None,
        "the outgoing node should still drain"
    );
    assert!(
        outcome.failures.is_empty(),
        "{} probes failed, {} were answered: {:?}",
        outcome.failures.len(),
        outcome.answered,
        outcome.failures
    );
}

#[test]
fn upgrades_in_place_without_failing_a_request() {
    let mut node = Managed::start("in-place");
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
    let mut node = Managed::start("no-successor");
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

/// A successor started by a node that was a successor itself is started
/// without the flags its predecessor gave that node.
#[test]
fn a_successor_upgrades_in_place_in_turn_without_failing_a_request() {
    let mut node = Managed::start("twice");
    node.tells_service_manager();
    let load = Load::start(node.proxy);
    std::thread::sleep(Duration::from_millis(300));
    node.signal("-USR2");
    let first = node.announced_successor();
    let replaced = node.exit();
    std::thread::sleep(Duration::from_millis(300));

    send_signal("-USR2", &first);
    let second = node.announced_successor();
    let first_stopped = eventually(|| !is_running(&first));
    std::thread::sleep(Duration::from_millis(300));
    let outcome = load.finish();

    assert!(
        replaced.is_some_and(|status| status.success()),
        "{replaced:?}"
    );
    assert_ne!(second, first);
    assert!(first_stopped, "the first successor did not stop");
    assert!(
        outcome.failures.is_empty(),
        "{} requests failed, {} were answered: {:?}",
        outcome.failures.len(),
        outcome.answered,
        outcome.failures
    );
    assert!(node.ops_get("/readyz").starts_with("HTTP/1.1 200"));
}

/// The successor parses its bootstrap config and takes the sockets, then
/// cannot start: its dynamic config is missing and there is no cache.
#[test]
fn keeps_serving_when_its_successor_fails_after_taking_the_sockets() {
    let mut node = Managed::start("fails-after-receipt");
    let bootstrap = std::fs::read_to_string(&node.bootstrap).unwrap();
    let unusable = bootstrap
        .replace("gfe-dynamic.json", "missing-dynamic.json")
        .replace("config-cache.json", "missing-cache.json");
    std::fs::write(&node.bootstrap, unusable).unwrap();

    node.signal("-USR2");
    let counted = eventually(|| {
        node.ops_get("/metrics")
            .contains("gfe_upgrade_failures_total 1")
    });

    assert!(counted, "the failed upgrade was not counted");
    assert_eq!(node.process.try_wait().unwrap(), None);
    assert!(http_get(node.proxy, "/").starts_with("HTTP/1.1 200"));
    assert!(node.ops_get("/readyz").starts_with("HTTP/1.1 200"));
}

/// Point the bootstrap config of `node`, which only a successor reads, at a
/// dynamic config that is a named pipe: reading it blocks, as reading a
/// file on a hung network file system does. Returns the pipe.
fn hang_the_successor_loading_its_config(node: &Managed) -> PathBuf {
    let pipe = node.bootstrap.with_file_name("hung-dynamic.json");
    let _ = std::fs::remove_file(&pipe);
    let made = Command::new("mkfifo").arg(&pipe).status().unwrap();
    assert!(made.success(), "mkfifo {}", pipe.display());
    let bootstrap = std::fs::read_to_string(&node.bootstrap).unwrap();
    let hung = bootstrap.replace("gfe-dynamic.json", "hung-dynamic.json");
    std::fs::write(&node.bootstrap, hung).unwrap();
    pipe
}

/// Wait until a process reads `pipe`, and keep it waiting for more: the
/// pipe opened for writing, with nothing written to it. `None` if no
/// process came to read within a while.
fn keep_its_reader_waiting(pipe: PathBuf) -> Option<std::fs::File> {
    let (opened, writer) = std::sync::mpsc::channel();
    // Opening a pipe blocks until it has a reader.
    std::thread::spawn(move || {
        let _ = opened.send(std::fs::OpenOptions::new().write(true).open(pipe));
    });
    writer.recv_timeout(Duration::from_secs(20)).ok()?.ok()
}

#[test]
fn stops_promptly_when_told_to_while_its_successor_is_starting() {
    let mut node = Managed::start("stop-while-upgrading");
    let pipe = hang_the_successor_loading_its_config(&node);
    node.signal("-USR2");
    // The successor has taken the sockets and said which process it is.
    let mut successor_config = keep_its_reader_waiting(pipe).expect("no successor started");

    let told = Instant::now();
    node.signal("-TERM");
    let stopped = node.exit();

    assert!(
        stopped.is_some_and(|status| status.success()),
        "the node did not stop cleanly: {stopped:?}"
    );
    assert!(
        told.elapsed() < Duration::from_secs(5),
        "{:?}",
        told.elapsed()
    );
    // Writing to a pipe nobody reads any more fails: the successor is gone.
    let successor_gone = eventually(|| successor_config.write_all(b" ").is_err());
    assert!(successor_gone, "the successor was not stopped");
}

#[test]
fn tells_the_service_manager_when_it_is_ready() {
    let node = Managed::start("ready");

    let told = node.tells_service_manager();

    assert!(told.contains(&"READY=1".to_string()), "{told:?}");
}

#[test]
fn tells_the_service_manager_which_process_has_taken_over() {
    let node = Managed::start("main-pid");
    node.tells_service_manager();

    node.signal("-USR2");
    let started = node.tells_service_manager();
    let finished = node.tells_service_manager();

    assert_eq!(started, ["RELOADING=1"]);
    let successor = finished
        .iter()
        .find_map(|line| line.strip_prefix("MAINPID="))
        .unwrap_or_else(|| panic!("no MAINPID in {finished:?}"));
    assert_ne!(successor, node.process.id().to_string());
    assert!(finished.contains(&"READY=1".to_string()), "{finished:?}");
}

#[test]
fn tells_the_service_manager_that_an_upgrade_failed() {
    let node = Managed::start("failed");
    node.tells_service_manager();
    std::fs::write(&node.bootstrap, "not a config").unwrap();

    node.signal("-USR2");
    node.tells_service_manager();
    let finished = node.tells_service_manager();

    // Ready again, as the same process, and saying why.
    assert!(finished.contains(&"READY=1".to_string()), "{finished:?}");
    assert!(
        !finished.iter().any(|line| line.starts_with("MAINPID=")),
        "{finished:?}"
    );
    assert!(
        finished.iter().any(|line| line
            .starts_with("STATUS=Upgrade failed, still serving: the successor went away")),
        "{finished:?}"
    );
}

/// The process id of the parent of process `pid`, as text.
fn parent_of(pid: &str) -> String {
    let ps = Command::new("ps")
        .args(["-o", "ppid=", "-p", pid])
        .output()
        .unwrap();
    String::from_utf8_lossy(&ps.stdout).trim().to_string()
}

#[test]
fn successor_is_no_child_of_the_node_when_it_is_announced() {
    let mut node = Managed::start_draining_for("detached", "8s");
    node.tells_service_manager();
    // A client that keeps its connection, and with it the node, around for
    // a while after the node has handed over.
    let mut client = TcpStream::connect(node.proxy).unwrap();
    request_on(&mut client).unwrap();

    node.signal("-USR2");
    node.tells_service_manager();
    let announced = node.tells_service_manager();
    let successor = announced
        .iter()
        .find_map(|line| line.strip_prefix("MAINPID="))
        .unwrap_or_else(|| panic!("no MAINPID in {announced:?}"));
    let parent = parent_of(successor);

    // A service manager takes a main process that is some other process's
    // child for one it cannot wait for, and kills it outright on stop.
    assert_eq!(node.process.try_wait().unwrap(), None);
    assert_ne!(parent, node.process.id().to_string());
}

/// Whether a node still serves a while after it was sent `signal`.
fn still_serves_after(signal: &str) -> bool {
    let mut node = Managed::start(&format!("signal{signal}"));

    node.signal(signal);
    std::thread::sleep(Duration::from_millis(500));

    node.process.try_wait().unwrap().is_none()
        && http_get(node.proxy, "/").starts_with("HTTP/1.1 200")
}

/// What operators send out of habit to make a daemon reload, and what log
/// rotation typically sends once it has rotated.
#[test]
fn keeps_serving_when_sent_a_hangup() {
    assert!(still_serves_after("-HUP"));
}

#[test]
fn keeps_serving_when_sent_the_other_user_signal() {
    assert!(still_serves_after("-USR1"));
}
