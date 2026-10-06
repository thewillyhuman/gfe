//! The product in one page: a node with an HTTPS and an HTTP listener in
//! front of a pool of two backends, driven as a client and an operator
//! would drive it. Each step says which feature it checks, so that a
//! failure names what broke.
#![cfg(unix)]

mod common;

use common::{Launch, Node, PATIENCE, eventually, free_addr, scratch};
use rustls::pki_types::{CertificateDer, ServerName};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// What both backends do with a request for `/slow`: hold it until the
/// test releases it.
#[derive(Default)]
struct Hold {
    /// Requests for `/slow` a backend has received.
    received: AtomicUsize,
    released: AtomicBool,
}

/// A backend named `name` on a loopback port, answering every request with
/// its name over HTTP/1.1 connections it keeps; its address.
fn backend(name: &'static str, hold: Arc<Hold>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let hold = Arc::clone(&hold);
            std::thread::spawn(move || serve_backend_connection(name, stream, &hold));
        }
    });
    addr
}

/// Answer the requests of one connection to a backend until it closes.
fn serve_backend_connection(name: &str, stream: TcpStream, hold: &Hold) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = stream;
    loop {
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
            return;
        }
        // The rest of the head; requests to the backends have no body.
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            if line == "\r\n" {
                break;
            }
        }
        if request_line.split(' ').nth(1) == Some("/slow") {
            hold.received.fetch_add(1, Ordering::SeqCst);
            while !hold.released.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{name}",
            name.len()
        );
        if writer.write_all(response.as_bytes()).is_err() {
            return;
        }
    }
}

/// A response, as a client got it.
#[derive(Debug)]
struct Response {
    status: u16,
    /// The status line and the header lines.
    head: String,
    body: String,
    /// The port of the client's end of the connection.
    client_port: u16,
}

impl Response {
    /// The value of header `name`, if the response has it.
    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }
}

/// Parse what a server sent before it closed the connection.
fn parse(received: &[u8], client_port: u16) -> Response {
    let text = String::from_utf8_lossy(received).to_string();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("not an HTTP response: {text:?}"));
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|status| status.parse().ok())
        .unwrap_or_else(|| panic!("no status in {head:?}"));
    Response {
        status,
        head: head.to_string(),
        body: body.to_string(),
        client_port,
    }
}

/// A TLS client that trusts `root` only.
fn tls_client(root: &CertificateDer<'static>) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root.clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

/// `GET path` with `Host: host` over HTTPS to `addr`, naming `host` in the
/// handshake, on a connection of its own, with `headers` added.
fn https_get(
    client: &Arc<rustls::ClientConfig>,
    addr: SocketAddr,
    host: &str,
    path: &str,
    headers: &str,
) -> Response {
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(PATIENCE)).unwrap();
    let client_port = tcp.local_addr().unwrap().port();
    let server_name = ServerName::try_from(host.to_string()).unwrap();
    let connection = rustls::ClientConnection::new(Arc::clone(client), server_name).unwrap();
    let mut tls = rustls::StreamOwned::new(connection, tcp);
    write!(
        tls,
        "GET {path} HTTP/1.1\r\nhost: {host}\r\nconnection: close\r\n{headers}\r\n"
    )
    .unwrap();
    let mut received = Vec::new();
    // A server that closes without `close_notify` ends the read with an
    // error; what came before it is the response.
    let _ = tls.read_to_end(&mut received);
    parse(&received, client_port)
}

/// `GET path` with `Host: host` over plain HTTP to `addr`.
fn http_get(addr: SocketAddr, host: &str, path: &str) -> Response {
    let mut tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(PATIENCE)).unwrap();
    let client_port = tcp.local_addr().unwrap().port();
    write!(
        tcp,
        "GET {path} HTTP/1.1\r\nhost: {host}\r\nconnection: close\r\n\r\n"
    )
    .unwrap();
    let mut received = Vec::new();
    tcp.read_to_end(&mut received).unwrap();
    parse(&received, client_port)
}

/// The dynamic config of the smoke test: HTTPS on `https` for
/// `smoke.test`, forwarded to the pool of `backends`; HTTP on `http`,
/// redirected to HTTPS; the certificate files in `dir`. `extra_route` is
/// added to the routes.
fn dynamic_config(
    dir: &Path,
    https: SocketAddr,
    http: SocketAddr,
    backends: [SocketAddr; 2],
    extra_route: &str,
) -> String {
    format!(
        r#"{{
  "certificates": [{{"default": true,
                     "cert_file": "{dir}/smoke.crt", "key_file": "{dir}/smoke.key"}}],
  "listeners": [
    {{"id": "https", "address": "127.0.0.1", "port": {https_port}, "protocol": "https"}},
    {{"id": "http", "address": "127.0.0.1", "port": {http_port}, "protocol": "http"}}
  ],
  "routes": [
    {extra_route}
    {{"id": "app", "listener": "https", "host": "smoke.test", "path_prefix": "/",
      "action": {{"forward": "backends"}}}},
    {{"id": "to-https", "listener": "http", "host": "*", "path_prefix": "/",
      "action": {{"redirect": {{"scheme": "https"}}}}}}
  ],
  "pools": [{{"id": "backends", "upstreams": [
    {{"host": "127.0.0.1", "port": {b0}}},
    {{"host": "127.0.0.1", "port": {b1}}}
  ]}}]
}}"#,
        dir = dir.display(),
        https_port = https.port(),
        http_port = http.port(),
        b0 = backends[0].port(),
        b1 = backends[1].port(),
    )
}

/// The JSON events of `target` in the log file `log`.
fn events(log: &Path, target: &str) -> Vec<serde_json::Value> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|event| event["target"] == target)
        .collect()
}

/// The value of the series of `name` whose labels include all of `labels`.
fn series(metrics: &str, name: &str, labels: &[&str]) -> Option<f64> {
    metrics.lines().find_map(|line| {
        let rest = line.strip_prefix(name)?.strip_prefix('{')?;
        let (series_labels, value) = rest.split_once("} ")?;
        labels
            .iter()
            .all(|label| series_labels.split(',').any(|l| l == *label))
            .then(|| value.parse().ok())?
    })
}

#[test]
fn a_node_serves_its_clients_from_start_to_stop() {
    let dir = scratch("smoke", "product");
    let certified =
        rcgen::generate_simple_self_signed(vec!["smoke.test".into(), "unknown.test".into()])
            .unwrap();
    std::fs::write(dir.join("smoke.crt"), certified.cert.pem()).unwrap();
    std::fs::write(dir.join("smoke.key"), certified.key_pair.serialize_pem()).unwrap();
    let client = tls_client(certified.cert.der());
    let hold = Arc::new(Hold::default());
    let backends = [
        backend("backend-a", Arc::clone(&hold)),
        backend("backend-b", Arc::clone(&hold)),
    ];
    let log = dir.join("gfe.log");
    // Chosen anew each time the node is started, as its HTTP port is.
    let https = Mutex::new(free_addr());
    let dynamic = |http| {
        let mut https = https.lock().unwrap();
        *https = free_addr();
        dynamic_config(&dir, *https, http, backends, "")
    };
    let extra = format!(
        "[log]\nfile = \"{}\"\n\n[timeouts]\ndrain_deadline = \"10s\"\n",
        log.display()
    );
    let mut node = Node::start(
        &dir,
        &Launch {
            extra: &extra,
            dynamic: &dynamic,
            ..Launch::default()
        },
    );
    let https = *https.lock().unwrap();

    // TLS termination, routing by host, forwarding to a pool.
    let request_id = "smoke-test-request-1";
    let proxied = https_get(
        &client,
        https,
        "smoke.test",
        "/",
        &format!("x-request-id: {request_id}\r\n"),
    );
    assert_eq!(proxied.status, 200, "proxying over HTTPS: {proxied:?}");
    assert!(
        proxied.body.starts_with("backend-"),
        "proxying over HTTPS: {proxied:?}"
    );

    // The redirect action.
    let redirected = http_get(node.proxy, "smoke.test", "/path?q=1");
    assert_eq!(redirected.status, 308, "redirecting HTTP: {redirected:?}");
    assert_eq!(
        redirected.header("location"),
        Some("https://smoke.test/path?q=1"),
        "redirecting HTTP: {redirected:?}"
    );

    // A host no route is for.
    let unknown = https_get(&client, https, "unknown.test", "/", "");
    assert_eq!(
        unknown.status, 404,
        "answering an unknown host: {unknown:?}"
    );
    assert!(
        unknown.header("x-request-id").is_some(),
        "answering an unknown host with a request id: {unknown:?}"
    );

    // The ops endpoints.
    assert!(
        node.ops_get("/readyz").starts_with("HTTP/1.1 200"),
        "readiness of a serving node"
    );
    let metrics = node.ops_get("/metrics");
    let counted = series(
        &metrics,
        "gfe_requests_total",
        &[
            r#"listener="https""#,
            r#"vhost="smoke.test""#,
            r#"route="app""#,
            r#"status="200""#,
        ],
    );
    assert_eq!(
        counted,
        Some(1.0),
        "counting the request under its listener, vhost and route:\n{metrics}"
    );

    // One access event and one connection event for the request.
    let logged = eventually(|| {
        let access = events(&log, "gfe::access");
        let conn = events(&log, "gfe::conn");
        access
            .iter()
            .filter(|event| event["fields"]["request_id"] == request_id)
            .count()
            == 1
            && conn
                .iter()
                .filter(|event| {
                    event["fields"]["listener"] == "https"
                        && event["fields"]["client_port"] == proxied.client_port
                })
                .count()
                == 1
    });
    assert!(
        logged,
        "logging the request (gfe::access) and its connection (gfe::conn):\n{}",
        std::fs::read_to_string(&log).unwrap_or_default()
    );

    // A config change, applied without a restart.
    let new_route = r#"{"id": "new", "listener": "https", "host": "smoke.test",
                        "path_prefix": "/new",
                        "action": {"fixed": {"status": 200, "body": "new route"}}},"#;
    let staged = dir.join("gfe-dynamic.json.staged");
    std::fs::write(
        &staged,
        dynamic_config(&dir, https, node.proxy, backends, new_route),
    )
    .unwrap();
    std::fs::rename(&staged, dir.join("gfe-dynamic.json")).unwrap();
    let reloaded =
        eventually(|| https_get(&client, https, "smoke.test", "/new", "").body == "new route");
    assert!(reloaded, "serving a route added to the dynamic config");

    // A drain: readiness fails at once, the request in flight completes, and
    // the node exits cleanly before its drain deadline.
    let in_flight = std::thread::spawn({
        let client = Arc::clone(&client);
        move || https_get(&client, https, "smoke.test", "/slow", "")
    });
    assert!(
        eventually(|| hold.received.load(Ordering::SeqCst) == 1),
        "a backend never got the slow request"
    );
    let told = Instant::now();
    node.signal("-TERM");
    assert!(
        eventually(|| node.ops_get("/readyz").starts_with("HTTP/1.1 503")),
        "failing readiness on SIGTERM"
    );
    hold.released.store(true, Ordering::SeqCst);
    let completed = in_flight.join().unwrap();
    assert_eq!(
        completed.status, 200,
        "completing the request in flight during a drain: {completed:?}"
    );
    let exit = node.exit();
    assert!(
        exit.is_some_and(|status| status.success()),
        "exiting cleanly after a drain: {exit:?}"
    );
    assert!(
        told.elapsed() < Duration::from_secs(10),
        "exiting within the drain deadline: {:?}",
        told.elapsed()
    );
}
