//! The edge in front of a trivial Pingora application: accepting, TLS,
//! HTTP/1 and HTTP/2, the client timeouts, the limits, reloads, the
//! handover of sockets, the drain, and what is counted and logged about
//! each connection.
//!
//! The application answers every request with what it learnt about it:
//! the method, the path, the addresses of its session, and whether the
//! connection was found in `Connections` under them. It tells the
//! connection when a request begins and ends, as the proxy does.

use async_trait::async_trait;
use bytes::Bytes;
use gfe_config::{LimitsConfig, ListenProtocol, Listener, ListenerId, TimeoutsConfig};
use gfe_proxy::listener::{Connections, Drain, Listeners, Shared, serve_plain};
use gfe_proxy::metrics::GfeMetrics;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use netkit_tls::{Acceptor, CertSpec, CertStore, MinVersion, SniResolver};
use pingora_core::apps::HttpServerOptions;
use pingora_core::apps::http_app::{HttpServer, ServeHttp};
use pingora_core::protocols::http::ServerSession;
use rustls::pki_types::{CertificateDer, ServerName};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

// ---------------------------------------------------------------------------
// The application
// ---------------------------------------------------------------------------

/// Answers every request with what it knows about it. `/slow/<ms>` takes
/// that long to answer.
struct Describe {
    connections: Arc<Connections>,
    shared: Arc<Shared>,
    /// Requests being answered right now.
    busy: Arc<AtomicUsize>,
}

/// Counts a request as being answered until dropped.
struct Busy(Arc<AtomicUsize>);

impl Drop for Busy {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl ServeHttp for Describe {
    async fn response(&self, session: &mut ServerSession) -> http::Response<Vec<u8>> {
        let client = session.client_addr().and_then(|a| a.as_inet()).copied();
        let server = session.server_addr().and_then(|a| a.as_inet()).copied();
        let conn = client
            .zip(server)
            .and_then(|(client, server)| self.connections.lookup(client, server));
        let _request = conn.as_ref().map(|conn| conn.begin_request());
        self.busy.fetch_add(1, Ordering::SeqCst);
        let _busy = Busy(self.busy.clone());
        let path = session.req_header().uri.path().to_string();
        if let Some(ms) = path.strip_prefix("/slow/") {
            let ms = ms.parse().expect("a number of milliseconds");
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
        // What the edge asks of the application: no keep-alive once the
        // node drains, also for a request that was in flight.
        if self.shared.is_draining() {
            session.set_keepalive(None);
        }
        let body = format!(
            "method={} path={path} version={:?} client={} server={} found={} listener={}",
            session.req_header().method,
            session.req_header().version,
            client.map_or("none".to_string(), |a| a.to_string()),
            server.map_or("none".to_string(), |a| a.to_string()),
            conn.is_some(),
            conn.map_or("none".to_string(), |conn| conn.listener().id.to_string()),
        );
        http::Response::builder()
            .status(200)
            .header("content-length", body.len())
            .body(body.into_bytes())
            .expect("a valid response")
    }
}

type App = HttpServer<Describe>;

fn app(connections: Arc<Connections>, shared: Arc<Shared>, busy: Arc<AtomicUsize>) -> Arc<App> {
    let mut app = HttpServer::new_app(Describe {
        connections,
        shared,
        busy,
    });
    let mut options = HttpServerOptions::default();
    options.h2c = true;
    app.server_options = Some(options);
    Arc::new(app)
}

// ---------------------------------------------------------------------------
// Certificates and TLS clients
// ---------------------------------------------------------------------------

const NAME: &str = "a.example.org";

/// A self-signed certificate for [`NAME`], written once per test binary.
struct TestCert {
    der: CertificateDer<'static>,
    entry: CertSpec,
}

fn cert() -> &'static TestCert {
    static CERT: OnceLock<TestCert> = OnceLock::new();
    CERT.get_or_init(|| {
        let cert = rcgen::generate_simple_self_signed(vec![NAME.to_string()]).unwrap();
        let dir = std::env::temp_dir().join(format!("gfe-core-edge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let entry = CertSpec {
            sni: vec![NAME.to_string()],
            default: true,
            cert_file: dir.join("tls.crt"),
            key_file: dir.join("tls.key"),
        };
        std::fs::write(&entry.cert_file, cert.cert.pem()).unwrap();
        std::fs::write(&entry.key_file, cert.key_pair.serialize_pem()).unwrap();
        TestCert {
            der: cert.cert.der().clone(),
            entry,
        }
    })
}

fn tls_acceptor(min_version: MinVersion) -> (Acceptor, Arc<SniResolver>) {
    let resolver = Arc::new(SniResolver::new(
        CertStore::build(std::slice::from_ref(&cert().entry)).unwrap(),
    ));
    let config = netkit_tls::server_config(resolver.clone(), min_version).unwrap();
    (Acceptor::new(Arc::new(config)), resolver)
}

/// A client trusting [`cert`], offering `versions` and `alpn`.
fn connector(
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn: &[&[u8]],
) -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert().der.clone()).unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(versions)
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    TlsConnector::from(Arc::new(config))
}

async fn tls_connect(
    addr: SocketAddr,
    alpn: &[&[u8]],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let tcp = TcpStream::connect(addr).await.unwrap();
    connector(rustls::DEFAULT_VERSIONS, alpn)
        .connect(ServerName::try_from(NAME).unwrap(), tcp)
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------
// The node under test
// ---------------------------------------------------------------------------

struct Node {
    listeners: Arc<Listeners<App>>,
    shared: Arc<Shared>,
    connections: Arc<Connections>,
    busy: Arc<AtomicUsize>,
    drain: Drain,
}

fn http_listener(id: &str) -> Listener {
    Listener {
        id: ListenerId(id.into()),
        address: "127.0.0.1".parse().unwrap(),
        port: 0,
        protocol: ListenProtocol::Http,
    }
}

/// A plaintext listener on a loopback port that was free a moment ago. A
/// listener is identified by the address it is configured on: two
/// listeners on port 0 would be one.
fn http_listener_on_free_port(id: &str) -> Listener {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    Listener {
        port: probe.local_addr().unwrap().port(),
        ..http_listener(id)
    }
}

fn https_listener(id: &str) -> Listener {
    Listener {
        protocol: ListenProtocol::Https,
        ..http_listener(id)
    }
}

fn shared_with(timeouts: TimeoutsConfig, limits: LimitsConfig) -> Arc<Shared> {
    let (_, resolver) = tls_acceptor(MinVersion::Tls12);
    Arc::new(Shared::new(Arc::new(GfeMetrics::new()), limits, timeouts).with_sni_resolver(resolver))
}

impl Node {
    fn start(listeners: &[Listener]) -> Self {
        Self::start_with(
            listeners,
            TimeoutsConfig::default(),
            LimitsConfig::default(),
            MinVersion::Tls12,
        )
    }

    fn start_with(
        listeners: &[Listener],
        timeouts: TimeoutsConfig,
        limits: LimitsConfig,
        min_version: MinVersion,
    ) -> Self {
        let shared = shared_with(timeouts, limits);
        let connections = Connections::new();
        let busy = Arc::new(AtomicUsize::new(0));
        let drain = Drain::new();
        let (tls, _) = tls_acceptor(min_version);
        let node = Node {
            listeners: Arc::new(Listeners::new(
                shared.clone(),
                app(connections.clone(), shared.clone(), busy.clone()),
                tls,
                connections.clone(),
                drain.subscribe(),
            )),
            shared,
            connections,
            busy,
            drain,
        };
        node.reconcile(listeners);
        node
    }

    fn reconcile(&self, listeners: &[Listener]) {
        let staged = self.listeners.stage(listeners).unwrap();
        self.listeners.commit(staged);
    }

    fn addr(&self, id: &str) -> SocketAddr {
        self.listeners
            .local_addr(&ListenerId(id.into()))
            .expect("the listener is running")
    }

    fn metrics(&self) -> String {
        self.shared.metrics().encode()
    }

    fn assert_metric(&self, expected: &str) {
        let metrics = self.metrics();
        assert!(
            metrics.contains(expected),
            "missing {expected} in:\n{metrics}"
        );
    }

    /// Wait until `n` requests are being answered.
    async fn until_requests_in_flight(&self, n: usize) {
        eventually(|| self.busy.load(Ordering::SeqCst) == n).await;
    }

    fn start_draining(&self) {
        self.drain.trigger(&self.shared);
    }
}

/// Wait for `condition`, polling, for at most five seconds.
async fn eventually(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "the condition never held");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

/// An HTTP/1.1 request for `path` that leaves the connection open.
fn get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nhost: {NAME}\r\n\r\n")
}

/// Whether `received` holds a whole HTTP/1 response: its head, and a body
/// of `content-length` bytes.
fn is_complete_response(received: &[u8]) -> bool {
    let text = String::from_utf8_lossy(received);
    let Some(head_end) = text.find("\r\n\r\n") else {
        return false;
    };
    let length = text[..head_end]
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    received.len() >= head_end + 4 + length
}

/// Read one HTTP/1 response.
async fn read_response<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut received = Vec::new();
    let mut chunk = [0u8; 4096];
    while !is_complete_response(&received) {
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .expect("a response should arrive")
            .unwrap();
        assert!(read > 0, "closed in the middle of a response: {received:?}");
        received.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8_lossy(&received).to_string()
}

/// Send `request` and read its response.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, request: &str) -> String {
    stream.write_all(request.as_bytes()).await.unwrap();
    read_response(stream).await
}

/// Read until the node closes the connection, at most a few seconds.
async fn read_until_closed<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => received.extend_from_slice(&chunk[..read]),
            }
        }
    })
    .await
    .expect("the node should have closed the connection");
    String::from_utf8_lossy(&received).to_string()
}

type H2Sender = hyper::client::conn::http2::SendRequest<Empty<Bytes>>;

/// An HTTP/2 connection over `io`, and the task driving it.
async fn h2_client<IO>(io: IO) -> (H2Sender, tokio::task::JoinHandle<hyper::Result<()>>)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
            .await
            .unwrap();
    (sender, tokio::spawn(conn))
}

async fn h2_get(sender: &mut H2Sender, scheme: &str, path: &str) -> (u16, String) {
    let request = http::Request::builder()
        .uri(format!("{scheme}://{NAME}{path}"))
        .body(Empty::new())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).to_string())
}

// ---------------------------------------------------------------------------
// Capturing the connection log
// ---------------------------------------------------------------------------

/// The JSON log lines emitted on this thread while the guard is alive.
#[derive(Clone, Default)]
struct CapturedLogs(Arc<std::sync::Mutex<Vec<u8>>>);

thread_local! {
    static CAPTURING: std::cell::RefCell<Option<CapturedLogs>> =
        const { std::cell::RefCell::new(None) };
}

/// Hands each log line to the test capturing on the thread that emitted it.
struct ToCapturingTest;

impl std::io::Write for ToCapturingTest {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        CAPTURING.with(|capturing| {
            if let Some(logs) = capturing.borrow().as_ref() {
                logs.0.lock().unwrap().extend_from_slice(buf);
            }
        });
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Stops capturing on this thread when dropped.
struct Capturing;

impl Drop for Capturing {
    fn drop(&mut self) {
        CAPTURING.with(|capturing| *capturing.borrow_mut() = None);
    }
}

impl CapturedLogs {
    /// Capture logs as the node emits them (JSON). Each test runs on a
    /// runtime of its own thread, so what this thread emits is what the
    /// test's edge logged. One subscriber serves the whole binary: `tracing`
    /// caches per callsite whether anybody listens.
    fn start() -> (CapturedLogs, Capturing) {
        static SUBSCRIBER: std::sync::Once = std::sync::Once::new();
        SUBSCRIBER.call_once(|| {
            tracing_subscriber::fmt()
                .json()
                .with_writer(|| ToCapturingTest)
                .init();
        });
        let logs = CapturedLogs::default();
        CAPTURING.with(|capturing| *capturing.borrow_mut() = Some(logs.clone()));
        (logs, Capturing)
    }

    /// The fields of the single `gfe::conn` event of the test, waiting for
    /// it to be emitted.
    async fn connection_event(&self) -> serde_json::Value {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let events = self.connection_events();
            assert!(
                events.len() < 2,
                "more than one connection event: {events:?}"
            );
            if let [event] = events.as_slice() {
                return event.clone();
            }
            assert!(Instant::now() < deadline, "no connection event was logged");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn connection_events(&self) -> Vec<serde_json::Value> {
        let raw = self.0.lock().unwrap().clone();
        String::from_utf8_lossy(&raw)
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|event| event["target"] == "gfe::conn")
            .map(|event| event["fields"].clone())
            .collect()
    }
}

/// Why the single connection of a test was closed.
async fn close_reason(logs: &CapturedLogs) -> String {
    logs.connection_event().await["reason"]
        .as_str()
        .unwrap()
        .to_string()
}

// ---------------------------------------------------------------------------
// Protocols
// ---------------------------------------------------------------------------

#[tokio::test]
async fn serves_two_http1_requests_on_one_kept_alive_connection() {
    let node = Node::start(&[http_listener("http")]);
    let mut stream = TcpStream::connect(node.addr("http")).await.unwrap();

    let first = exchange(&mut stream, &get("/one")).await;
    let second = exchange(&mut stream, &get("/two")).await;

    assert!(first.starts_with("HTTP/1.1 200"), "{first}");
    assert!(
        first.contains("method=GET path=/one version=HTTP/1.1"),
        "{first}"
    );
    assert!(second.contains("path=/two"), "{second}");
    node.assert_metric(r#"gfe_connections_accepted_total{listener="http"} 1"#);
}

#[tokio::test]
async fn serves_http2_with_prior_knowledge_on_a_plain_listener() {
    let node = Node::start(&[http_listener("http")]);
    let tcp = TcpStream::connect(node.addr("http")).await.unwrap();
    let (mut sender, _conn) = h2_client(tcp).await;

    let (status, body) = h2_get(&mut sender, "http", "/h2c").await;

    assert_eq!(status, 200);
    assert!(body.contains("path=/h2c version=HTTP/2.0"), "{body}");
    assert!(body.contains("found=true"), "{body}");
}

#[tokio::test]
async fn serves_a_request_shorter_than_the_http2_preface() {
    let node = Node::start(&[http_listener("http")]);
    let mut stream = TcpStream::connect(node.addr("http")).await.unwrap();

    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.contains(" 200 "), "{response}");
}

#[tokio::test]
async fn serves_http1_over_tls() {
    let node = Node::start(&[https_listener("https")]);
    let mut stream = tls_connect(node.addr("https"), &[b"http/1.1"]).await;

    let response = exchange(&mut stream, &get("/secure")).await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("found=true"), "{response}");
}

#[tokio::test]
async fn serves_http2_over_tls_chosen_by_alpn() {
    let node = Node::start(&[https_listener("https")]);
    let tls = tls_connect(node.addr("https"), &[b"h2", b"http/1.1"]).await;
    let (mut sender, _conn) = h2_client(tls).await;

    let (status, body) = h2_get(&mut sender, "https", "/secure").await;

    assert_eq!(status, 200);
    assert!(body.contains("version=HTTP/2.0"), "{body}");
    assert!(body.contains("found=true"), "{body}");
}

// ---------------------------------------------------------------------------
// The connection of a request
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_request_finds_its_connection_by_the_addresses_of_its_session() {
    let node = Node::start(&[http_listener("http")]);
    let mut stream = TcpStream::connect(node.addr("http")).await.unwrap();

    let response = exchange(&mut stream, &get("/")).await;

    let client = stream.local_addr().unwrap();
    let server = stream.peer_addr().unwrap();
    let expected = format!("client={client} server={server} found=true listener=http");
    assert!(response.contains(&expected), "{response}");
}

#[tokio::test]
async fn an_ipv4_client_of_a_dual_stack_listener_is_found_by_its_ipv4_addresses() {
    if std::net::TcpListener::bind("[::]:0").is_err() {
        eprintln!("no IPv6 on this host: skipped");
        return;
    }
    let mut listener = http_listener("any");
    listener.address = "::".parse().unwrap();
    let node = Node::start(&[listener]);
    let port = node.addr("any").port();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

    let response = exchange(&mut stream, &get("/")).await;

    let client = stream.local_addr().unwrap();
    let expected = format!("client={client} server=127.0.0.1:{port} found=true");
    assert!(response.contains(&expected), "{response}");
}

// ---------------------------------------------------------------------------
// TLS handshakes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn plain_http_to_a_tls_listener_is_counted_and_logged_as_a_failed_handshake() {
    let (logs, _guard) = CapturedLogs::start();
    let node = Node::start(&[https_listener("https")]);
    let mut stream = TcpStream::connect(node.addr("https")).await.unwrap();

    stream.write_all(get("/").as_bytes()).await.unwrap();
    read_until_closed(&mut stream).await;
    let event = logs.connection_event().await;

    assert_eq!(event["reason"], "tls_handshake_failed");
    assert_eq!(event["tls_error"], "invalid_message");
    assert_eq!(event["proto"], "https");
    assert!(event["error"].is_string(), "{event}");
    node.assert_metric(r#"gfe_tls_handshake_failures_total{reason="invalid_message"} 1"#);
    node.assert_metric(r#"gfe_tls_handshakes_total{result="failed"} 1"#);
    node.assert_metric(
        r#"gfe_connections_closed_total{listener="https",reason="tls_handshake_failed"} 1"#,
    );
}

#[tokio::test]
async fn a_client_without_a_version_in_common_is_counted_by_reason() {
    let (logs, _guard) = CapturedLogs::start();
    let node = Node::start_with(
        &[https_listener("https")],
        TimeoutsConfig::default(),
        LimitsConfig::default(),
        MinVersion::Tls13,
    );
    let tcp = TcpStream::connect(node.addr("https")).await.unwrap();

    let connected = connector(&[&rustls::version::TLS12], &[b"http/1.1"])
        .connect(ServerName::try_from(NAME).unwrap(), tcp)
        .await;
    let event = logs.connection_event().await;

    assert!(connected.is_err());
    assert_eq!(event["reason"], "tls_handshake_failed");
    assert_eq!(event["tls_error"], "peer_incompatible");
    node.assert_metric(r#"gfe_tls_handshake_failures_total{reason="peer_incompatible"} 1"#);
}

#[tokio::test]
async fn a_handshake_that_never_completes_is_closed_after_tls_handshake() {
    let (logs, _guard) = CapturedLogs::start();
    let timeouts = TimeoutsConfig {
        tls_handshake: Duration::from_millis(150),
        ..Default::default()
    };
    let node = Node::start_with(
        &[https_listener("https")],
        timeouts,
        LimitsConfig::default(),
        MinVersion::Tls12,
    );
    let mut stream = TcpStream::connect(node.addr("https")).await.unwrap();
    let started = Instant::now();

    read_until_closed(&mut stream).await;

    let after = started.elapsed();
    assert!(after >= Duration::from_millis(140), "{after:?}");
    assert_eq!(close_reason(&logs).await, "tls_handshake_timeout");
    node.assert_metric(r#"gfe_connections_rejected_total{reason="handshake_timeout"} 1"#);
}

#[tokio::test]
async fn a_successful_handshake_is_counted_by_its_parameters() {
    let node = Node::start(&[https_listener("https")]);
    let mut stream = tls_connect(node.addr("https"), &[b"http/1.1"]).await;

    exchange(&mut stream, &get("/")).await;

    node.assert_metric(r#"gfe_tls_handshakes_total{result="ok"} 1"#);
    node.assert_metric("gfe_tls_handshake_duration_seconds_count 1");
    node.assert_metric(r#"alpn="http/1.1",resumed="false"} 1"#);
    node.assert_metric(r#"gfe_tls_connections_total{version="TLSv1.3""#);
}

#[tokio::test]
async fn counts_handshakes_that_found_no_certificate() {
    // No default certificate: a client asking for an unknown name gets none.
    let resolver = Arc::new(SniResolver::new(CertStore::default()));
    let config = netkit_tls::server_config(resolver.clone(), MinVersion::Tls12).unwrap();
    let shared = Arc::new(
        Shared::new(
            Arc::new(GfeMetrics::new()),
            LimitsConfig::default(),
            TimeoutsConfig::default(),
        )
        .with_sni_resolver(resolver),
    );
    let connections = Connections::new();
    let drain = Drain::new();
    let listeners = Listeners::new(
        shared.clone(),
        app(connections.clone(), shared.clone(), Arc::default()),
        Acceptor::new(Arc::new(config)),
        connections,
        drain.subscribe(),
    );
    listeners.commit(listeners.stage(&[https_listener("https")]).unwrap());
    let addr = listeners.local_addr(&ListenerId("https".into())).unwrap();
    let tcp = TcpStream::connect(addr).await.unwrap();

    let connected = connector(rustls::DEFAULT_VERSIONS, &[b"http/1.1"])
        .connect(ServerName::try_from(NAME).unwrap(), tcp)
        .await;

    assert!(connected.is_err());
    eventually(|| {
        shared
            .metrics()
            .encode()
            .contains("gfe_tls_sni_no_cert_total 1")
    })
    .await;
}

// ---------------------------------------------------------------------------
// Client timeouts
// ---------------------------------------------------------------------------

fn timeouts(request_header_ms: u64, client_idle_ms: u64) -> TimeoutsConfig {
    TimeoutsConfig {
        request_header: Duration::from_millis(request_header_ms),
        client_idle: Duration::from_millis(client_idle_ms),
        ..Default::default()
    }
}

fn start_plain_with(timeouts: TimeoutsConfig) -> Node {
    Node::start_with(
        &[http_listener("http")],
        timeouts,
        LimitsConfig::default(),
        MinVersion::Tls12,
    )
}

#[tokio::test]
async fn a_connection_that_sends_nothing_is_closed_after_request_header() {
    let (logs, _guard) = CapturedLogs::start();
    let node = start_plain_with(timeouts(150, 10_000));
    let mut stream = TcpStream::connect(node.addr("http")).await.unwrap();
    let started = Instant::now();

    let received = read_until_closed(&mut stream).await;
    let event = logs.connection_event().await;

    let after = started.elapsed();
    assert_eq!(received, "");
    assert!(after >= Duration::from_millis(140), "{after:?}");
    assert_eq!(event["reason"], "header_timeout");
    assert_eq!(event["requests"], 0);
}

#[tokio::test]
async fn a_kept_alive_connection_with_nothing_in_flight_is_closed_after_client_idle() {
    let (logs, _guard) = CapturedLogs::start();
    let node = start_plain_with(timeouts(10_000, 150));
    let mut stream = TcpStream::connect(node.addr("http")).await.unwrap();
    exchange(&mut stream, &get("/")).await;
    let answered = Instant::now();

    let rest = read_until_closed(&mut stream).await;

    let after = answered.elapsed();
    assert_eq!(rest, "");
    assert!(after >= Duration::from_millis(140), "{after:?}");
    assert_eq!(close_reason(&logs).await, "idle_timeout");
}

#[tokio::test]
async fn an_idle_http2_connection_is_sent_goaway_after_client_idle() {
    let (logs, _guard) = CapturedLogs::start();
    let node = start_plain_with(timeouts(10_000, 150));
    let tcp = TcpStream::connect(node.addr("http")).await.unwrap();
    let (mut sender, conn) = h2_client(tcp).await;
    h2_get(&mut sender, "http", "/").await;

    // The client keeps its side open: only the node can end the connection.
    let ended = tokio::time::timeout(Duration::from_secs(3), conn).await;

    assert!(ended.is_ok(), "the node did not end the connection");
    assert_eq!(close_reason(&logs).await, "idle_timeout");
}

#[tokio::test]
async fn a_slow_request_in_flight_is_closed_by_neither_timeout() {
    let node = start_plain_with(timeouts(100, 100));
    let mut stream = TcpStream::connect(node.addr("http")).await.unwrap();

    let response = exchange(&mut stream, &get("/slow/500")).await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// A connection that has been answered once and is still open; `None` if
/// the node closed it instead of serving it.
async fn try_open_connection(addr: SocketAddr) -> Option<TcpStream> {
    let mut stream = TcpStream::connect(addr).await.ok()?;
    stream.write_all(get("/").as_bytes()).await.ok()?;
    let mut received = Vec::new();
    let mut chunk = [0u8; 4096];
    while !is_complete_response(&received) {
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .expect("the node should answer a connection or close it")
            .ok()?;
        if read == 0 {
            return None;
        }
        received.extend_from_slice(&chunk[..read]);
    }
    received.starts_with(b"HTTP/1.1 200").then_some(stream)
}

fn start_limited(limits: LimitsConfig) -> Node {
    Node::start_with(
        &[http_listener("a"), http_listener_on_free_port("b")],
        TimeoutsConfig::default(),
        limits,
        MinVersion::Tls12,
    )
}

#[tokio::test]
async fn closes_connections_beyond_the_node_wide_limit() {
    let node = start_limited(LimitsConfig {
        max_connections: 1,
        ..Default::default()
    });
    let _held = try_open_connection(node.addr("a")).await.unwrap();

    let beyond = try_open_connection(node.addr("b")).await;

    assert!(beyond.is_none());
    node.assert_metric(r#"gfe_connections_rejected_total{reason="limit"} 1"#);
}

#[tokio::test]
async fn closes_connections_beyond_the_limit_of_a_listener() {
    let node = start_limited(LimitsConfig {
        max_connections_listener: 1,
        ..Default::default()
    });
    let _held = try_open_connection(node.addr("a")).await.unwrap();

    let beyond = try_open_connection(node.addr("a")).await;
    let elsewhere = try_open_connection(node.addr("b")).await;

    assert!(beyond.is_none());
    assert!(elsewhere.is_some());
    node.assert_metric(r#"gfe_connections_rejected_total{reason="limit"} 1"#);
}

#[tokio::test]
async fn a_closed_connection_makes_room_for_the_next() {
    let node = start_limited(LimitsConfig {
        max_connections: 1,
        ..Default::default()
    });
    let first = try_open_connection(node.addr("a")).await.unwrap();

    drop(first);

    // The node gives the place back once it has noticed the client is gone.
    let deadline = Instant::now() + Duration::from_secs(5);
    while try_open_connection(node.addr("a")).await.is_none() {
        assert!(Instant::now() < deadline, "the place was never given back");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ---------------------------------------------------------------------------
// Reload
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_reload_adds_a_listener() {
    let node = Node::start(&[http_listener("a")]);

    node.reconcile(&[http_listener("a"), http_listener_on_free_port("b")]);
    let mut stream = TcpStream::connect(node.addr("b")).await.unwrap();
    let response = exchange(&mut stream, &get("/")).await;

    assert!(response.contains("listener=b"), "{response}");
}

#[tokio::test]
async fn a_removed_listener_refuses_new_connections_and_keeps_serving_its_open_one() {
    let node = Node::start(&[http_listener("a"), http_listener_on_free_port("b")]);
    let addr = node.addr("b");
    let mut open = TcpStream::connect(addr).await.unwrap();
    exchange(&mut open, &get("/")).await;

    node.reconcile(&[http_listener("a")]);
    let again = exchange(&mut open, &get("/again")).await;
    let mut refused = false;
    for _ in 0..100 {
        if TcpStream::connect(addr).await.is_err() {
            refused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert!(again.contains("path=/again"), "{again}");
    assert!(refused, "the removed listener still accepts");
}

#[tokio::test]
async fn an_unchanged_listener_accepts_through_reloads_without_a_gap() {
    let node = Node::start(&[http_listener("a")]);
    let addr = node.addr("a");
    let extras = [
        http_listener_on_free_port("extra0"),
        http_listener_on_free_port("extra1"),
    ];
    let reloading = async {
        for i in 0..50 {
            node.reconcile(&[http_listener("a"), extras[i % 2].clone()]);
            tokio::task::yield_now().await;
        }
    };
    let connecting = async {
        for _ in 0..50 {
            let mut stream = TcpStream::connect(addr).await.expect("no gap in accepting");
            let response = exchange(&mut stream, &get("/")).await;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        }
    };

    tokio::join!(reloading, connecting);

    assert_eq!(node.addr("a"), addr);
}

#[tokio::test]
async fn a_reload_that_cannot_bind_changes_nothing() {
    let node = Node::start(&[http_listener("a")]);
    let addr = node.addr("a");
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut unbindable = http_listener("b");
    unbindable.port = taken.local_addr().unwrap().port();
    // Same address, so the same socket.
    let renamed = http_listener("renamed");

    let staged = node.listeners.stage(&[renamed, unbindable]);

    assert!(staged.is_err());
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let response = exchange(&mut stream, &get("/")).await;
    assert!(response.contains("listener=a"), "{response}");
    assert!(node.listeners.local_addr(&ListenerId("b".into())).is_none());
}

#[tokio::test]
async fn a_renamed_listener_names_the_next_requests_without_rebinding() {
    let node = Node::start(&[http_listener("a")]);
    let addr = node.addr("a");
    let mut open = TcpStream::connect(addr).await.unwrap();
    exchange(&mut open, &get("/")).await;

    // Same address, so the same socket.
    let renamed = http_listener("renamed");
    node.reconcile(&[renamed]);
    let on_open = exchange(&mut open, &get("/")).await;
    let mut fresh = TcpStream::connect(addr).await.unwrap();
    let on_fresh = exchange(&mut fresh, &get("/")).await;

    assert_eq!(node.addr("renamed"), addr);
    assert!(on_open.contains("listener=renamed"), "{on_open}");
    assert!(on_fresh.contains("listener=renamed"), "{on_fresh}");
}

#[tokio::test]
async fn a_listener_switched_to_https_terminates_tls_from_the_next_connection() {
    let node = Node::start(&[http_listener("a")]);
    let addr = node.addr("a");
    let mut plain = TcpStream::connect(addr).await.unwrap();
    exchange(&mut plain, &get("/")).await;

    let secure = https_listener("a");
    node.reconcile(&[secure]);
    let still_plain = exchange(&mut plain, &get("/plain")).await;
    let mut tls = tls_connect(addr, &[b"http/1.1"]).await;
    let over_tls = exchange(&mut tls, &get("/tls")).await;

    assert_eq!(node.addr("a"), addr);
    assert!(still_plain.contains("path=/plain"), "{still_plain}");
    assert!(over_tls.contains("path=/tls"), "{over_tls}");
}

// ---------------------------------------------------------------------------
// Handing the sockets over
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_successor_serves_connections_on_the_sockets_it_adopts() {
    let first = Node::start(&[http_listener("a")]);
    let addr = first.addr("a");
    let sockets = first.listeners.sockets().unwrap();
    first.start_draining();
    first.listeners.serve_until_drained().await;
    // Waits in the socket's queue: served only if the successor accepts on
    // that very socket.
    let mut queued = TcpStream::connect(addr).await.unwrap();

    let successor = Node::start(&[]);
    successor.listeners.adopt(sockets);
    successor.reconcile(&[http_listener("a")]);
    let response = exchange(&mut queued, &get("/")).await;

    assert!(response.contains("found=true listener=a"), "{response}");
    assert_eq!(successor.addr("a"), addr);
}

// ---------------------------------------------------------------------------
// Drain
// ---------------------------------------------------------------------------

fn start_draining_within(deadline_ms: u64) -> Node {
    start_plain_with(TimeoutsConfig {
        drain_deadline: Duration::from_millis(deadline_ms),
        ..Default::default()
    })
}

#[tokio::test]
async fn a_request_in_flight_when_draining_is_answered_with_connection_close() {
    let (logs, _guard) = CapturedLogs::start();
    let node = Node::start(&[http_listener("http")]);
    let mut stream = TcpStream::connect(node.addr("http")).await.unwrap();
    stream.write_all(get("/slow/300").as_bytes()).await.unwrap();
    node.until_requests_in_flight(1).await;

    node.start_draining();
    let response = read_until_closed(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response.to_ascii_lowercase().contains("connection: close"),
        "{response}"
    );
    assert_eq!(close_reason(&logs).await, "drain");
}

#[tokio::test]
async fn an_http2_connection_gets_goaway_and_its_stream_in_flight_completes() {
    let node = Node::start(&[http_listener("http")]);
    let tcp = TcpStream::connect(node.addr("http")).await.unwrap();
    let (mut sender, conn) = h2_client(tcp).await;
    // The client keeps its side open: only the node can end the connection.
    let _client = sender.clone();
    let response = tokio::spawn(async move { h2_get(&mut sender, "http", "/slow/300").await });
    node.until_requests_in_flight(1).await;

    node.start_draining();
    let (status, body) = response.await.unwrap();
    let ended = tokio::time::timeout(Duration::from_secs(5), conn).await;

    assert_eq!(status, 200);
    assert!(body.contains("path=/slow/300"), "{body}");
    assert!(ended.is_ok(), "the node did not end the connection");
}

#[tokio::test]
async fn an_idle_connection_may_send_one_more_request_and_is_closed_after_it() {
    let node = start_draining_within(2_000);
    let mut stream = TcpStream::connect(node.addr("http")).await.unwrap();
    exchange(&mut stream, &get("/")).await;

    node.start_draining();
    tokio::time::sleep(Duration::from_millis(100)).await;
    stream.write_all(get("/last").as_bytes()).await.unwrap();
    let last = read_until_closed(&mut stream).await;

    assert!(last.contains("path=/last"), "{last}");
    assert!(
        last.to_ascii_lowercase().contains("connection: close"),
        "{last}"
    );
}

#[tokio::test]
async fn an_idle_connection_is_closed_half_way_through_the_drain() {
    let (logs, _guard) = CapturedLogs::start();
    let node = start_draining_within(400);
    let mut stream = TcpStream::connect(node.addr("http")).await.unwrap();
    exchange(&mut stream, &get("/")).await;

    node.start_draining();
    let started = Instant::now();
    let rest = read_until_closed(&mut stream).await;

    let after = started.elapsed();
    assert_eq!(rest, "");
    assert!(after >= Duration::from_millis(180), "{after:?}");
    assert!(after < Duration::from_millis(400), "{after:?}");
    assert_eq!(close_reason(&logs).await, "drain");
}

#[tokio::test]
async fn serve_until_drained_returns_as_soon_as_the_last_connection_is_gone() {
    let node = start_draining_within(10_000);
    let mut stream = TcpStream::connect(node.addr("http")).await.unwrap();
    exchange(&mut stream, &get("/")).await;

    node.start_draining();
    let started = Instant::now();
    let client_leaves = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(stream);
    };
    tokio::join!(node.listeners.serve_until_drained(), client_leaves);

    let after = started.elapsed();
    assert!(after < Duration::from_secs(2), "{after:?}");
    node.assert_metric("gfe_connections_active 0");
}

#[tokio::test]
async fn a_connection_still_open_at_the_deadline_is_cut_and_counted_as_shutdown() {
    let (logs, _guard) = CapturedLogs::start();
    let node = start_draining_within(300);
    let mut stream = TcpStream::connect(node.addr("http")).await.unwrap();
    stream
        .write_all(get("/slow/10000").as_bytes())
        .await
        .unwrap();
    node.until_requests_in_flight(1).await;

    node.start_draining();
    let started = Instant::now();
    node.listeners.serve_until_drained().await;
    let returned_after = started.elapsed();
    let rest = read_until_closed(&mut stream).await;

    assert!(
        returned_after >= Duration::from_millis(290),
        "{returned_after:?}"
    );
    assert!(
        returned_after < Duration::from_millis(1_000),
        "{returned_after:?}"
    );
    assert_eq!(rest, "");
    assert_eq!(close_reason(&logs).await, "shutdown");
    node.assert_metric(r#"gfe_connections_closed_total{listener="http",reason="shutdown"} 1"#);
    node.assert_metric("gfe_connections_active 0");
    assert!(node.connections.is_empty());
}

#[tokio::test]
async fn a_draining_node_stops_accepting() {
    let node = Node::start(&[http_listener("http")]);
    let addr = node.addr("http");

    node.start_draining();
    node.listeners.serve_until_drained().await;

    assert!(TcpStream::connect(addr).await.is_err());
}

// ---------------------------------------------------------------------------
// The connection log
// ---------------------------------------------------------------------------

#[tokio::test]
async fn logs_and_counts_a_plain_connection() {
    let (logs, _guard) = CapturedLogs::start();
    let node = Node::start(&[http_listener("http")]);
    let mut stream = TcpStream::connect(node.addr("http")).await.unwrap();
    let request = format!("GET / HTTP/1.1\r\nhost: {NAME}\r\nconnection: close\r\n\r\n");

    stream.write_all(request.as_bytes()).await.unwrap();
    let response = read_until_closed(&mut stream).await;
    let event = logs.connection_event().await;

    assert_eq!(event["reason"], "closed");
    assert_eq!(event["listener"], "http");
    assert_eq!(event["proto"], "http");
    assert_eq!(event["client"], "127.0.0.1");
    assert_eq!(event["client_port"], stream.local_addr().unwrap().port());
    assert_eq!(event["requests"], 1);
    assert_eq!(event["bytes_in"], request.len());
    assert_eq!(event["bytes_out"], response.len());
    assert!(event["duration_ms"].as_f64().unwrap() > 0.0, "{event}");
    assert!(event.get("tls_version").is_none(), "{event}");
    assert!(event.get("accept_wait_ms").is_none(), "{event}");
    node.assert_metric(r#"gfe_connections_closed_total{listener="http",reason="closed"} 1"#);
    node.assert_metric(&format!(
        r#"gfe_bytes_in_total{{listener="http"}} {}"#,
        request.len()
    ));
    node.assert_metric(&format!(
        r#"gfe_bytes_out_total{{listener="http"}} {}"#,
        response.len()
    ));
    node.assert_metric(r#"gfe_connection_duration_seconds_count{listener="http"} 1"#);
    node.assert_metric("gfe_connections_active 0");
    node.assert_metric(r#"gfe_listener_connections_active{listener="http"} 0"#);
}

#[tokio::test]
async fn logs_the_tls_parameters_of_a_tls_connection() {
    let (logs, _guard) = CapturedLogs::start();
    let node = Node::start(&[https_listener("https")]);
    let mut stream = tls_connect(node.addr("https"), &[b"http/1.1"]).await;

    exchange(&mut stream, &get("/")).await;
    drop(stream);
    let event = logs.connection_event().await;

    assert_eq!(event["proto"], "https");
    assert_eq!(event["tls_version"], "TLSv1.3");
    assert_eq!(event["alpn"], "http/1.1");
    assert_eq!(event["sni"], NAME);
    assert_eq!(event["tls_resumed"], false);
    assert!(event["tls_handshake_ms"].as_f64().unwrap() > 0.0, "{event}");
    let cipher = event["tls_cipher"].as_str().unwrap();
    assert!(cipher.starts_with("TLS13_"), "{event}");
    assert_eq!(event["requests"], 1);
    assert!(event["bytes_in"].as_u64().unwrap() > 0, "{event}");
}

// ---------------------------------------------------------------------------
// The node's own endpoints
// ---------------------------------------------------------------------------

#[tokio::test]
async fn serve_plain_answers_up_to_its_connection_cap_and_stops_when_told() {
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let shared = shared_with(TimeoutsConfig::default(), LimitsConfig::default());
    let app = app(Connections::new(), shared.clone(), Arc::default());
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(async move { serve_plain(&socket, app, 1, stopped).await });

    let held = try_open_connection(addr).await;
    let beyond = try_open_connection(addr).await;
    stop.send_replace(true);
    let returned = tokio::time::timeout(Duration::from_secs(5), serving).await;

    let mut held = held.expect("the first connection is served");
    assert!(beyond.is_none());
    assert!(returned.is_ok());
    // Not a client connection: neither registered nor counted.
    let response = exchange(&mut held, &get("/")).await;
    assert!(response.contains("found=false"), "{response}");
    let metrics = shared.metrics().encode();
    assert!(
        !metrics.contains("gfe_connections_accepted_total{"),
        "{metrics}"
    );
}
