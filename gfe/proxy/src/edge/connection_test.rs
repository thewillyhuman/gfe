use super::*;
use crate::edge::test_support::{
    CapturedLogs, Describe, NAME, TestCert, acceptor, connector, eventually, exchange, get,
    listener, read_until_closed, shared,
};
use arc_swap::ArcSwap;
use gfe_config::{LimitsConfig, ListenProtocol};
use netkit_http::body::BodyExt;
use rustls::pki_types::ServerName;
use std::sync::OnceLock;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

// ---------------------------------------------------------------------------
// Socket options and HTTP options
// ---------------------------------------------------------------------------

#[test]
fn probes_a_peer_silent_for_client_idle() {
    let keepalive = tcp_keepalive(Duration::from_secs(42));

    assert_eq!(keepalive.idle, Duration::from_secs(42));
}

#[test]
fn gives_up_on_a_dead_peer_within_client_idle() {
    let keepalive = tcp_keepalive(Duration::from_secs(40));

    // Three probes ten seconds apart: gone for 30 s after the 40 s of
    // silence, not for the kernel's default of many minutes.
    assert_eq!(keepalive.interval, Duration::from_secs(10));
    assert_eq!(keepalive.probes, 3);
}

#[test]
fn never_asks_the_kernel_for_less_than_a_second() {
    let keepalive = tcp_keepalive(Duration::from_millis(200));

    assert_eq!(keepalive.idle, Duration::from_secs(1));
    assert_eq!(keepalive.interval, Duration::from_secs(1));
}

#[tokio::test]
async fn the_kernel_takes_the_keepalive_of_an_accepted_socket() {
    let (_client, server) = tcp_pair().await;
    let keepalive = tcp_keepalive(Duration::from_millis(200));

    let set = netkit_listen::keep_alive(
        &server,
        keepalive.idle,
        keepalive.interval,
        keepalive.probes,
    );

    assert!(set.is_ok(), "{set:?}");
}

#[test]
fn holds_http_to_the_client_timeouts_and_limits() {
    let timeouts = TimeoutsConfig {
        request_header: Duration::from_secs(5),
        client_idle: Duration::from_secs(40),
        drain_deadline: Duration::from_secs(30),
        ..Default::default()
    };
    let limits = LimitsConfig {
        max_header_bytes: 16_384,
        max_h2_concurrent_streams: 7,
        ..Default::default()
    };

    let options = http_options(&timeouts, &limits);

    assert_eq!(options.header_timeout, Duration::from_secs(5));
    assert_eq!(options.idle_timeout, Duration::from_secs(40));
    // A PING is answered within a quarter of client_idle.
    assert_eq!(options.keep_alive_timeout, Duration::from_secs(10));
    // Half the drain for one more request, half for answering it.
    assert_eq!(options.drain_idle_grace, Duration::from_secs(15));
    assert_eq!(options.max_header_bytes, 16_384);
    assert_eq!(options.max_concurrent_streams, 7);
}

#[test]
fn refuses_to_be_built_with_options_http_cannot_serve() {
    let limits = LimitsConfig {
        max_header_bytes: 100,
        ..Default::default()
    };
    let shared = Arc::new(Shared::new(
        Arc::new(crate::metrics::GfeMetrics::new()),
        limits,
        TimeoutsConfig::default(),
    ));

    let edge = Edge::new(shared, Arc::new(Describe::default()), acceptor(&[]).0);

    assert!(edge.is_err());
}

// ---------------------------------------------------------------------------
// The edge under test
// ---------------------------------------------------------------------------

fn cert() -> &'static TestCert {
    static CERT: OnceLock<TestCert> = OnceLock::new();
    CERT.get_or_init(|| TestCert::new(NAME))
}

/// Both ends of a loopback TCP connection: `(client, server)`.
async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (client, server)
}

/// An edge serving with [`Describe`], and the node's drain signal.
struct Node {
    edge: Arc<Edge<Describe>>,
    handler: Arc<Describe>,
    drain: watch::Sender<bool>,
}

impl Node {
    /// An edge serving the test certificate.
    fn start(timeouts: TimeoutsConfig) -> Self {
        Node::serving(&[cert()], timeouts)
    }

    fn serving(certs: &[&TestCert], timeouts: TimeoutsConfig) -> Self {
        let (tls, resolver) = acceptor(certs);
        let handler = Arc::new(Describe::default());
        let edge = Edge::new(shared(timeouts, resolver), Arc::clone(&handler), tls)
            .expect("the default limits can be served");
        Node {
            edge: Arc::new(edge),
            handler,
            drain: watch::channel(false).0,
        }
    }

    fn metrics(&self) -> String {
        self.edge.shared().metrics().encode()
    }

    fn assert_metric(&self, expected: &str) {
        let metrics = self.metrics();
        assert!(
            metrics.contains(expected),
            "missing {expected} in:\n{metrics}"
        );
    }

    /// Accept one connection on `configured`, serve it in a task of its
    /// own, and return the client's end and the task.
    async fn connect(
        &self,
        configured: &Arc<ArcSwap<Listener>>,
    ) -> (TcpStream, tokio::task::JoinHandle<()>) {
        let (client, stream) = tcp_pair().await;
        let accepted = Accepted {
            peer: stream.peer_addr().unwrap(),
            local: stream.local_addr().unwrap(),
            stream,
            listener: Arc::clone(configured),
            drain: self.drain.subscribe(),
        };
        let edge = Arc::clone(&self.edge);
        let serving = tokio::spawn(async move { edge.serve(accepted).await });
        (client, serving)
    }

    async fn connect_plain(&self) -> (TcpStream, tokio::task::JoinHandle<()>) {
        self.connect(&configured(ListenProtocol::Http)).await
    }

    async fn connect_tls(
        &self,
        alpn: &[&[u8]],
    ) -> (
        tokio_rustls::client::TlsStream<TcpStream>,
        tokio::task::JoinHandle<()>,
    ) {
        let (tcp, serving) = self.connect(&configured(ListenProtocol::Https)).await;
        let tls = connector(&[cert()], alpn)
            .connect(ServerName::try_from(NAME).unwrap(), tcp)
            .await
            .unwrap();
        (tls, serving)
    }
}

/// A listener as configured, named after its protocol.
fn configured(protocol: ListenProtocol) -> Arc<ArcSwap<Listener>> {
    let id = match protocol {
        ListenProtocol::Http => "http",
        ListenProtocol::Https => "https",
    };
    Arc::new(ArcSwap::from_pointee(listener(id, protocol)))
}

fn timeouts(request_header_ms: u64, client_idle_ms: u64) -> TimeoutsConfig {
    TimeoutsConfig {
        request_header: Duration::from_millis(request_header_ms),
        client_idle: Duration::from_millis(client_idle_ms),
        ..Default::default()
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
// Serving
// ---------------------------------------------------------------------------

#[tokio::test]
async fn hands_each_request_its_connection() {
    let node = Node::start(TimeoutsConfig::default());
    let (mut client, _serving) = node.connect_plain().await;

    let response = exchange(&mut client, &get("/one")).await;

    let expected = format!(
        "path=/one version=HTTP/1.1 client={} local={} listener=http",
        client.local_addr().unwrap(),
        client.peer_addr().unwrap()
    );
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains(&expected), "{response}");
    assert!(!node.handler.seen()[0].is_tls());
}

#[tokio::test]
async fn serves_http2_with_prior_knowledge_on_a_plain_listener() {
    let node = Node::start(TimeoutsConfig::default());
    let (client, _serving) = node.connect_plain().await;
    let mut sender = h2_client(client).await;

    let (status, body) = h2_get(&mut sender, "http", "/h2c").await;

    assert_eq!(status, 200);
    assert!(body.contains("path=/h2c version=HTTP/2.0"), "{body}");
}

#[tokio::test]
async fn hands_each_request_on_tls_what_the_handshake_negotiated() {
    let node = Node::start(TimeoutsConfig::default());
    let (mut client, _serving) = node.connect_tls(&[b"http/1.1"]).await;

    let response = exchange(&mut client, &get("/secure")).await;

    let conn = &node.handler.seen()[0];
    assert!(response.contains("listener=https"), "{response}");
    assert!(conn.is_tls());
    assert_eq!(conn.sni(), Some(NAME));
    assert_eq!(conn.tls().unwrap().alpn.as_deref(), Some("http/1.1"));
}

#[tokio::test]
async fn serves_http2_over_tls_chosen_by_alpn() {
    let node = Node::start(TimeoutsConfig::default());
    let (client, _serving) = node.connect_tls(&[b"h2", b"http/1.1"]).await;
    let mut sender = h2_client(client).await;

    let (status, body) = h2_get(&mut sender, "https", "/secure").await;

    assert_eq!(status, 200);
    assert!(body.contains("version=HTTP/2.0"), "{body}");
}

#[tokio::test]
async fn a_renamed_listener_is_seen_by_the_next_request_on_an_open_connection() {
    let node = Node::start(TimeoutsConfig::default());
    let configured = configured(ListenProtocol::Http);
    let (mut client, _serving) = node.connect(&configured).await;
    let before = exchange(&mut client, &get("/")).await;

    configured.store(Arc::new(listener("renamed", ListenProtocol::Http)));
    let after = exchange(&mut client, &get("/")).await;

    assert!(before.contains("listener=http"), "{before}");
    assert!(after.contains("listener=renamed"), "{after}");
}

#[tokio::test]
async fn a_listener_switched_to_tls_terminates_it_from_the_next_connection() {
    let node = Node::start(TimeoutsConfig::default());
    let configured = configured(ListenProtocol::Http);
    let (mut plain, _serving) = node.connect(&configured).await;
    exchange(&mut plain, &get("/")).await;

    configured.store(Arc::new(listener("http", ListenProtocol::Https)));
    let still_plain = exchange(&mut plain, &get("/plain")).await;
    let (tcp, _serving) = node.connect(&configured).await;
    let mut tls = connector(&[cert()], &[b"http/1.1"])
        .connect(ServerName::try_from(NAME).unwrap(), tcp)
        .await
        .unwrap();
    let over_tls = exchange(&mut tls, &get("/tls")).await;

    assert!(still_plain.contains("path=/plain"), "{still_plain}");
    assert!(over_tls.contains("path=/tls"), "{over_tls}");
}

// ---------------------------------------------------------------------------
// What is counted and logged
// ---------------------------------------------------------------------------

#[tokio::test]
async fn logs_and_counts_a_plain_connection() {
    let (logs, _capturing) = CapturedLogs::start();
    let node = Node::start(TimeoutsConfig::default());
    let (mut client, _serving) = node.connect_plain().await;
    let request = format!("GET / HTTP/1.1\r\nhost: {NAME}\r\nconnection: close\r\n\r\n");

    client.write_all(request.as_bytes()).await.unwrap();
    let response = read_until_closed(&mut client).await;
    let event = logs.connection_event().await;

    assert_eq!(event["reason"], "closed");
    assert_eq!(event["listener"], "http");
    assert_eq!(event["proto"], "http");
    assert_eq!(event["client"], "127.0.0.1");
    assert_eq!(event["client_port"], client.local_addr().unwrap().port());
    assert_eq!(event["requests"], 1);
    assert_eq!(event["bytes_in"], request.len());
    assert_eq!(event["bytes_out"], response.len());
    assert!(event["duration_ms"].as_f64().unwrap() > 0.0, "{event}");
    assert!(event.get("tls_version").is_none(), "{event}");
    assert!(event.get("accept_wait_ms").is_none(), "{event}");
    node.assert_metric(r#"gfe_connections_accepted_total{listener="http"} 1"#);
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
async fn counts_the_requests_of_a_kept_alive_connection() {
    let (logs, _capturing) = CapturedLogs::start();
    let node = Node::start(TimeoutsConfig::default());
    let (mut client, _serving) = node.connect_plain().await;

    exchange(&mut client, &get("/one")).await;
    exchange(&mut client, &get("/two")).await;
    drop(client);
    let event = logs.connection_event().await;

    assert_eq!(event["requests"], 2);
    assert_eq!(event["reason"], "closed");
}

#[tokio::test]
async fn logs_and_counts_the_tls_parameters_of_a_tls_connection() {
    let (logs, _capturing) = CapturedLogs::start();
    let node = Node::start(TimeoutsConfig::default());
    let (mut client, _serving) = node.connect_tls(&[b"http/1.1"]).await;

    exchange(&mut client, &get("/")).await;
    drop(client);
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
    node.assert_metric(r#"gfe_tls_handshakes_total{result="ok"} 1"#);
    node.assert_metric("gfe_tls_handshake_duration_seconds_count 1");
    node.assert_metric(r#"alpn="http/1.1",resumed="false"} 1"#);
    node.assert_metric(r#"gfe_tls_connections_total{version="TLSv1.3""#);
}

#[tokio::test]
async fn plain_http_to_a_tls_listener_is_a_failed_handshake() {
    let (logs, _capturing) = CapturedLogs::start();
    let node = Node::start(TimeoutsConfig::default());
    let (mut client, _serving) = node.connect(&configured(ListenProtocol::Https)).await;

    client.write_all(get("/").as_bytes()).await.unwrap();
    read_until_closed(&mut client).await;
    let event = logs.connection_event().await;

    assert_eq!(event["reason"], "tls_handshake_failed");
    assert_eq!(event["tls_error"], "invalid_message");
    assert_eq!(event["proto"], "https");
    assert!(event["error"].is_string(), "{event}");
    node.assert_metric(r#"gfe_tls_handshake_failures_total{reason="invalid_message"} 1"#);
    node.assert_metric(
        r#"gfe_connections_closed_total{listener="https",reason="tls_handshake_failed"} 1"#,
    );
}

#[tokio::test]
async fn a_handshake_that_never_completes_is_closed_after_tls_handshake() {
    let (logs, _capturing) = CapturedLogs::start();
    let node = Node::start(TimeoutsConfig {
        tls_handshake: Duration::from_millis(100),
        ..Default::default()
    });
    let started = Instant::now();
    let (mut client, _serving) = node.connect(&configured(ListenProtocol::Https)).await;

    read_until_closed(&mut client).await;

    let after = started.elapsed();
    assert!(after >= Duration::from_millis(90), "{after:?}");
    assert_eq!(close_reason(&logs).await, "tls_handshake_timeout");
    node.assert_metric(r#"gfe_connections_rejected_total{reason="handshake_timeout"} 1"#);
}

#[tokio::test]
async fn counts_the_handshakes_that_found_no_certificate() {
    // No certificate at all: not even a default one to fall back on.
    let node = Node::serving(&[], TimeoutsConfig::default());
    let (tcp, _serving) = node.connect(&configured(ListenProtocol::Https)).await;

    let connected = connector(&[cert()], &[b"http/1.1"])
        .connect(ServerName::try_from(NAME).unwrap(), tcp)
        .await;

    assert!(connected.is_err());
    eventually(|| node.metrics().contains("gfe_tls_sni_no_cert_total 1")).await;
}

// ---------------------------------------------------------------------------
// Why connections end
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_client_that_sends_nothing_is_closed_after_request_header() {
    let (logs, _capturing) = CapturedLogs::start();
    let node = Node::start(timeouts(100, 10_000));
    let started = Instant::now();
    let (mut client, _serving) = node.connect_plain().await;

    let received = read_until_closed(&mut client).await;
    let event = logs.connection_event().await;

    let after = started.elapsed();
    assert_eq!(received, "");
    assert!(after >= Duration::from_millis(90), "{after:?}");
    assert_eq!(event["reason"], "header_timeout");
    assert_eq!(event["requests"], 0);
}

#[tokio::test]
async fn a_kept_alive_client_with_nothing_in_flight_is_closed_after_client_idle() {
    let (logs, _capturing) = CapturedLogs::start();
    let node = Node::start(timeouts(10_000, 100));
    let (mut client, _serving) = node.connect_plain().await;
    exchange(&mut client, &get("/")).await;
    let answered = Instant::now();

    let rest = read_until_closed(&mut client).await;

    let after = answered.elapsed();
    assert_eq!(rest, "");
    assert!(after >= Duration::from_millis(90), "{after:?}");
    assert_eq!(close_reason(&logs).await, "idle_timeout");
}

#[tokio::test]
async fn a_slow_request_in_flight_is_closed_by_neither_timeout() {
    let node = Node::start(timeouts(50, 50));
    let (mut client, _serving) = node.connect_plain().await;

    let response = exchange(&mut client, &get("/slow/200")).await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}

#[tokio::test]
async fn a_client_that_leaves_in_the_middle_of_a_request_head_aborted() {
    let (logs, _capturing) = CapturedLogs::start();
    let node = Node::start(TimeoutsConfig::default());
    let (mut client, _serving) = node.connect_plain().await;

    client
        .write_all(b"GET / HTTP/1.1\r\nhost: a")
        .await
        .unwrap();
    client.shutdown().await.unwrap();
    read_until_closed(&mut client).await;

    assert_eq!(close_reason(&logs).await, "client_abort");
}

#[tokio::test]
async fn a_malformed_request_is_answered_400_and_a_protocol_error() {
    let (logs, _capturing) = CapturedLogs::start();
    let node = Node::start(TimeoutsConfig::default());
    let (mut client, _serving) = node.connect_plain().await;

    client.write_all(b"NOT HTTP AT ALL\r\n\r\n").await.unwrap();
    let response = read_until_closed(&mut client).await;
    let event = logs.connection_event().await;

    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert_eq!(event["reason"], "protocol_error");
    assert_eq!(event["requests"], 0);
    assert!(event["error"].is_string(), "{event}");
    assert!(node.handler.seen().is_empty());
}

#[tokio::test]
async fn a_request_in_flight_when_draining_is_answered_and_the_connection_drained() {
    let (logs, _capturing) = CapturedLogs::start();
    let node = Node::start(TimeoutsConfig::default());
    let (mut client, _serving) = node.connect_plain().await;
    client.write_all(get("/slow/100").as_bytes()).await.unwrap();
    node.handler.until_busy_with(1).await;

    node.drain.send_replace(true);
    let response = read_until_closed(&mut client).await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response.to_ascii_lowercase().contains("connection: close"),
        "{response}"
    );
    assert_eq!(close_reason(&logs).await, "drain");
}

#[tokio::test]
async fn a_connection_cut_before_it_ended_is_shutdown() {
    let (logs, _capturing) = CapturedLogs::start();
    let node = Node::start(TimeoutsConfig::default());
    let (mut client, serving) = node.connect_plain().await;
    client
        .write_all(get("/slow/10000").as_bytes())
        .await
        .unwrap();
    node.handler.until_busy_with(1).await;

    // What netkit-listen does at the drain deadline.
    serving.abort();
    let rest = read_until_closed(&mut client).await;

    assert_eq!(rest, "");
    assert_eq!(close_reason(&logs).await, "shutdown");
    node.assert_metric(r#"gfe_connections_closed_total{listener="http",reason="shutdown"} 1"#);
    node.assert_metric("gfe_connections_active 0");
}

#[tokio::test]
async fn a_tls_connection_the_node_closes_ends_with_close_notify() {
    let node = Node::start(timeouts(100, 10_000));
    let (mut client, _serving) = node.connect_tls(&[b"http/1.1"]).await;

    // The node gives up on a client that sends no request.
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut rest))
        .await
        .unwrap();

    // rustls reports an end that no `close_notify` announced as an error.
    assert!(ended.is_ok(), "closed without close_notify: {ended:?}");
}

#[tokio::test]
async fn a_tls_connection_cut_ends_with_close_notify() {
    let node = Node::start(TimeoutsConfig::default());
    let (mut client, serving) = node.connect_tls(&[b"http/1.1"]).await;
    client
        .write_all(get("/slow/10000").as_bytes())
        .await
        .unwrap();
    node.handler.until_busy_with(1).await;

    serving.abort();
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut rest))
        .await
        .unwrap();

    assert!(ended.is_ok(), "closed without close_notify: {ended:?}");
}

#[tokio::test]
async fn a_refused_connection_is_counted_as_rejected() {
    let node = Node::start(TimeoutsConfig::default());
    let refused_on = listener("http", ListenProtocol::Http);

    node.edge.refused(&refused_on, Limit::MaxConnections);
    node.edge
        .refused(&refused_on, Limit::MaxConnectionsPerListener);

    node.assert_metric(r#"gfe_connections_rejected_total{reason="limit"} 2"#);
}

#[tokio::test]
async fn a_connection_refused_for_its_clients_rate_is_counted_apart() {
    let node = Node::start(TimeoutsConfig::default());
    let refused_on = listener("http", ListenProtocol::Http);

    node.edge.refused(&refused_on, Limit::ConnectionsPerPeer);

    node.assert_metric(r#"gfe_connections_rejected_total{reason="client_rate"} 1"#);
}

// ---------------------------------------------------------------------------
// HTTP/2 clients
// ---------------------------------------------------------------------------

type H2Sender = hyper::client::conn::http2::SendRequest<http_body_util::Empty<netkit_http::Bytes>>;

/// An HTTP/2 connection over `io`, driven by a task of its own.
async fn h2_client<IO>(io: IO) -> H2Sender
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(io),
    )
    .await
    .unwrap();
    tokio::spawn(conn);
    sender
}

async fn h2_get(sender: &mut H2Sender, scheme: &str, path: &str) -> (u16, String) {
    let request = netkit_http::Request::builder()
        .uri(format!("{scheme}://{NAME}{path}"))
        .body(http_body_util::Empty::new())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}
