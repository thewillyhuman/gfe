//! End-to-end Phase 1 integration tests: a real GFE proxy in front of a mock
//! upstream, exercised over plaintext HTTP and over TLS.

use bytes::Bytes;
use gfe_metrics::GfeMetrics;
use gfe_proxy::{ListenerSet, ProxyShared};
use gfe_types::{
    CertEntry, DynamicConfig, LimitsConfig, ListenProtocol, Listener, ListenerId, PoolId, Route,
    RouteAction, RouteId, Scheme, TimeoutsConfig, TlsConfig, Upstream, UpstreamPool,
};
use gfe_upstream::UpstreamClient;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// Spawn a mock upstream that echoes the `X-Forwarded-For` and `Host` headers
/// so tests can assert forwarding behaviour.
async fn spawn_upstream() -> SocketAddr {
    spawn_upstream_answering_after(Duration::ZERO).await
}

/// Like [`spawn_upstream`], but each response is delayed by `delay`.
async fn spawn_upstream_answering_after(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| async move {
                    tokio::time::sleep(delay).await;
                    let xff = req
                        .headers()
                        .get("x-forwarded-for")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("none")
                        .to_string();
                    let host = req
                        .headers()
                        .get("host")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("none")
                        .to_string();
                    let body = format!("upstream-ok xff={xff} host={host}");
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    addr
}

fn self_signed_files(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let cert = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
    let dir = std::env::temp_dir();
    let tag = format!("gfe-e2e-{}-{}", std::process::id(), name.replace('.', "_"));
    let cp = dir.join(format!("{tag}.crt"));
    let kp = dir.join(format!("{tag}.key"));
    std::fs::write(&cp, cert.cert.pem()).unwrap();
    std::fs::write(&kp, cert.key_pair.serialize_pem()).unwrap();
    (cp, kp)
}

fn build_shared() -> Arc<ProxyShared> {
    build_shared_with(TimeoutsConfig::default(), LimitsConfig::default())
}

fn build_shared_with(timeouts: TimeoutsConfig, limits: LimitsConfig) -> Arc<ProxyShared> {
    Arc::new(ProxyShared::new(
        UpstreamClient::new(16).unwrap(),
        Arc::new(GfeMetrics::new()),
        limits,
        timeouts,
        TlsConfig::default(),
    ))
}

/// Apply `cfg` and start its listeners; returns the listener set (to
/// reconcile further configs against) and the shutdown sender.
fn start_listeners(
    cfg: &DynamicConfig,
    shared: Arc<ProxyShared>,
) -> (ListenerSet, watch::Sender<bool>) {
    gfe_config::apply(&shared, cfg).expect("apply config");
    let server_config = Arc::new(
        gfe_tls::server_config(shared.resolver.clone(), gfe_types::MinVersion::Tls12).unwrap(),
    );
    let (tx, rx) = watch::channel(false);
    let listeners = ListenerSet::new(shared, server_config, rx);
    reconcile(&listeners, &cfg.listeners);
    (listeners, tx)
}

/// Make `desired` the running listeners, as a config reload would.
fn reconcile(listeners: &ListenerSet, desired: &[Listener]) {
    listeners.commit(listeners.stage(desired).expect("bind"));
}

/// Start a proxy serving `cfg`; returns the address of its first listener
/// and the shutdown sender.
async fn start_proxy(
    cfg: &DynamicConfig,
    shared: Arc<ProxyShared>,
) -> (SocketAddr, watch::Sender<bool>) {
    let (listeners, tx) = start_listeners(cfg, shared);
    let proxy_addr = listeners.local_addr(&cfg.listeners[0].id).unwrap();
    (proxy_addr, tx)
}

async fn http_get(addr: SocketAddr, host: &str, path: &str) -> (u16, String) {
    let stream = TcpStream::connect(addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .uri(path)
        .header("host", host)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).to_string())
}

#[tokio::test]
async fn proxies_http_request_to_upstream() {
    let upstream = spawn_upstream().await;
    let cfg = DynamicConfig {
        listeners: vec![Listener {
            id: ListenerId("http".into()),
            address: "127.0.0.1".parse().unwrap(),
            port: 0,
            protocol: ListenProtocol::Http,
        }],
        routes: vec![Route {
            id: RouteId("web".into()),
            listener: ListenerId("http".into()),
            host: "a.example.org".into(),
            path_prefix: "/".into(),
            action: RouteAction::Forward("pool".into()),
        }],
        pools: vec![UpstreamPool {
            id: PoolId("pool".into()),
            scheme: Scheme::Http,
            lb_policy: Default::default(),
            upstreams: vec![Upstream {
                host: upstream.ip().to_string(),
                port: upstream.port(),
                weight: 1,
            }],
            health_check: None,
        }],
        ..Default::default()
    };

    let shared = build_shared();
    let (proxy_addr, _tx) = start_proxy(&cfg, shared).await;

    let (status, body) = http_get(proxy_addr, "a.example.org", "/").await;
    assert_eq!(status, 200, "body: {body}");
    assert!(body.contains("upstream-ok"), "body: {body}");
    // Forwarding header was added with the client's loopback IP.
    assert!(body.contains("xff=127.0.0.1"), "body: {body}");
}

#[tokio::test]
async fn unmatched_host_returns_404() {
    let upstream = spawn_upstream().await;
    let cfg = DynamicConfig {
        listeners: vec![Listener {
            id: ListenerId("http".into()),
            address: "127.0.0.1".parse().unwrap(),
            port: 0,
            protocol: ListenProtocol::Http,
        }],
        routes: vec![Route {
            id: RouteId("web".into()),
            listener: ListenerId("http".into()),
            host: "a.example.org".into(),
            path_prefix: "/".into(),
            action: RouteAction::Forward("pool".into()),
        }],
        pools: vec![UpstreamPool {
            id: PoolId("pool".into()),
            scheme: Scheme::Http,
            lb_policy: Default::default(),
            upstreams: vec![Upstream {
                host: upstream.ip().to_string(),
                port: upstream.port(),
                weight: 1,
            }],
            health_check: None,
        }],
        ..Default::default()
    };
    let shared = build_shared();
    let (proxy_addr, _tx) = start_proxy(&cfg, shared).await;

    let (status, _body) = http_get(proxy_addr, "unknown.example.org", "/").await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn http_redirect_action() {
    let cfg = DynamicConfig {
        listeners: vec![Listener {
            id: ListenerId("http".into()),
            address: "127.0.0.1".parse().unwrap(),
            port: 0,
            protocol: ListenProtocol::Http,
        }],
        routes: vec![Route {
            id: RouteId("redir".into()),
            listener: ListenerId("http".into()),
            host: "*".into(),
            path_prefix: "/".into(),
            action: RouteAction::Redirect(gfe_types::RedirectAction {
                scheme: "https".into(),
                status: 308,
            }),
        }],
        ..Default::default()
    };
    let shared = build_shared();
    let (proxy_addr, _tx) = start_proxy(&cfg, shared).await;

    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .uri("/path")
        .header("host", "a.example.org")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 308);
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "https://a.example.org/path"
    );
}

#[tokio::test]
async fn terminates_tls_and_proxies() {
    let upstream = spawn_upstream().await;
    let (cp, kp) = self_signed_files("secure.example.org");

    let cfg = DynamicConfig {
        certificates: vec![CertEntry {
            sni: vec!["secure.example.org".into()],
            default: false,
            cert_file: cp.clone(),
            key_file: kp,
        }],
        listeners: vec![Listener {
            id: ListenerId("https".into()),
            address: "127.0.0.1".parse().unwrap(),
            port: 0,
            protocol: ListenProtocol::Https,
        }],
        routes: vec![Route {
            id: RouteId("web".into()),
            listener: ListenerId("https".into()),
            host: "secure.example.org".into(),
            path_prefix: "/".into(),
            action: RouteAction::Forward("pool".into()),
        }],
        pools: vec![UpstreamPool {
            id: PoolId("pool".into()),
            scheme: Scheme::Http,
            lb_policy: Default::default(),
            upstreams: vec![Upstream {
                host: upstream.ip().to_string(),
                port: upstream.port(),
                weight: 1,
            }],
            health_check: None,
        }],
    };
    let shared = build_shared();
    let (proxy_addr, _tx) = start_proxy(&cfg, shared).await;

    let (status, text) = https_get(proxy_addr, &cp, "secure.example.org").await;

    assert_eq!(status, 200);
    assert!(text.contains("upstream-ok"), "body: {text}");
}

/// `GET /` over TLS (HTTP/1.1), trusting the certificate in `cert_file` and
/// sending `server_name` as SNI and `Host`. The connection is closed on return.
async fn https_get(
    addr: SocketAddr,
    cert_file: &std::path::Path,
    server_name: &str,
) -> (u16, String) {
    use tokio_rustls::TlsConnector;

    let cert_pem = std::fs::read(cert_file).unwrap();
    let mut reader = std::io::BufReader::new(&cert_pem[..]);
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut reader) {
        roots.add(c.unwrap()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(client_cfg));

    let tcp = TcpStream::connect(addr).await.unwrap();
    let domain = rustls::pki_types::ServerName::try_from(server_name.to_string()).unwrap();
    let tls = connector.connect(domain, tcp).await.unwrap();
    let io = TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    let conn = tokio::spawn(conn);
    let req = Request::builder()
        .uri("/")
        .header("host", server_name)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    drop(sender);
    let _ = conn.await;
    (status, String::from_utf8_lossy(&body).to_string())
}

#[tokio::test]
async fn serves_acme_http01_challenge() {
    let cfg = DynamicConfig {
        listeners: vec![Listener {
            id: ListenerId("http".into()),
            address: "127.0.0.1".parse().unwrap(),
            port: 0,
            protocol: ListenProtocol::Http,
        }],
        routes: vec![Route {
            id: RouteId("redir".into()),
            listener: ListenerId("http".into()),
            host: "*".into(),
            path_prefix: "/".into(),
            action: RouteAction::Redirect(gfe_types::RedirectAction {
                scheme: "https".into(),
                status: 308,
            }),
        }],
        ..Default::default()
    };
    let shared = build_shared();
    // Register a pending ACME challenge.
    shared.challenges.set("tok-abc", "tok-abc.keyauthz");
    let (proxy_addr, _tx) = start_proxy(&cfg, shared).await;

    // The challenge is served (not redirected), even though the catch-all
    // route would otherwise redirect to https.
    let (status, body) = http_get(
        proxy_addr,
        "any.example.org",
        "/.well-known/acme-challenge/tok-abc",
    )
    .await;
    assert_eq!(status, 200);
    assert!(body.contains("tok-abc.keyauthz"), "body: {body}");

    // Unknown token → 404.
    let (status, _) = http_get(
        proxy_addr,
        "any.example.org",
        "/.well-known/acme-challenge/nope",
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn health_failover_excludes_dead_backend() {
    use gfe_health::HealthChecker;
    use gfe_types::{HealthCheckConfig, ProbeType};

    // One healthy upstream, one dead (closed port).
    let good = spawn_upstream().await;
    let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead_listener.local_addr().unwrap().port();
    drop(dead_listener);

    let fast_hc = HealthCheckConfig {
        probe_type: ProbeType::Http,
        interval: Duration::from_millis(30),
        timeout: Duration::from_millis(300),
        healthy_threshold: 1,
        unhealthy_threshold: 2,
        path: "/".into(),
        expected_status: 200,
        drain_status: None,
    };
    let cfg = DynamicConfig {
        listeners: vec![Listener {
            id: ListenerId("http".into()),
            address: "127.0.0.1".parse().unwrap(),
            port: 0,
            protocol: ListenProtocol::Http,
        }],
        routes: vec![Route {
            id: RouteId("web".into()),
            listener: ListenerId("http".into()),
            host: "a.example.org".into(),
            path_prefix: "/".into(),
            action: RouteAction::Forward("pool".into()),
        }],
        pools: vec![UpstreamPool {
            id: PoolId("pool".into()),
            scheme: Scheme::Http,
            lb_policy: Default::default(),
            upstreams: vec![
                Upstream {
                    host: "127.0.0.1".into(),
                    port: good.port(),
                    weight: 1,
                },
                Upstream {
                    host: "127.0.0.1".into(),
                    port: dead_port,
                    weight: 1,
                },
            ],
            health_check: Some(fast_hc.clone()),
        }],
        ..Default::default()
    };

    let shared = build_shared();
    // Run the health checker against the pool.
    let checker = HealthChecker::new(shared.health.clone(), shared.metrics.clone());
    checker.reconcile(&cfg.pools, &fast_hc);

    let (proxy_addr, _tx) = start_proxy(&cfg, shared.clone()).await;

    // Wait until the dead backend is marked unhealthy.
    let mut excluded = false;
    for _ in 0..100 {
        if !shared.health.is_selectable("127.0.0.1", dead_port) {
            excluded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(excluded, "dead backend should be marked unhealthy");

    // All requests now succeed (routed only to the healthy backend).
    for _ in 0..6 {
        let (status, body) = http_get(proxy_addr, "a.example.org", "/").await;
        assert_eq!(status, 200, "body: {body}");
        assert!(body.contains("upstream-ok"), "body: {body}");
    }
    checker.stop_all();
}

/// One plaintext listener answering every request with a fixed `200 ok`:
/// enough to exercise connection handling without an upstream.
fn fixed_response_config() -> DynamicConfig {
    DynamicConfig {
        listeners: vec![Listener {
            id: ListenerId("http".into()),
            address: "127.0.0.1".parse().unwrap(),
            port: 0,
            protocol: ListenProtocol::Http,
        }],
        routes: vec![Route {
            id: RouteId("fixed".into()),
            listener: ListenerId("http".into()),
            host: "*".into(),
            path_prefix: "/".into(),
            action: RouteAction::Fixed(gfe_types::FixedAction {
                status: 200,
                body: "ok".into(),
            }),
        }],
        ..Default::default()
    }
}

/// Read until the server closes the connection, failing the test if it is
/// still open after a few seconds.
async fn read_until_closed(stream: &mut TcpStream) -> String {
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut received))
        .await
        .expect("server should have closed the connection")
        .unwrap();
    String::from_utf8_lossy(&received).to_string()
}

#[tokio::test]
async fn closes_connection_that_never_sends_a_request() {
    let timeouts = TimeoutsConfig {
        request_header: Duration::from_millis(200),
        ..Default::default()
    };
    let shared = build_shared_with(timeouts, LimitsConfig::default());
    let (proxy_addr, _tx) = start_proxy(&fixed_response_config(), shared).await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let received = read_until_closed(&mut stream).await;

    assert_eq!(received, "");
}

#[tokio::test]
async fn closes_keep_alive_connection_idle_for_client_idle() {
    let timeouts = TimeoutsConfig {
        client_idle: Duration::from_millis(200),
        ..Default::default()
    };
    let shared = build_shared_with(timeouts, LimitsConfig::default());
    let (proxy_addr, _tx) = start_proxy(&fixed_response_config(), shared).await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nhost: a.example.org\r\n\r\n")
        .await
        .unwrap();
    let received = read_until_closed(&mut stream).await;

    assert!(received.starts_with("HTTP/1.1 200"), "{received}");
}

#[tokio::test]
async fn serves_request_that_takes_longer_than_client_idle() {
    let upstream = spawn_upstream_answering_after(Duration::from_millis(600)).await;
    let cfg = DynamicConfig {
        listeners: vec![Listener {
            id: ListenerId("http".into()),
            address: "127.0.0.1".parse().unwrap(),
            port: 0,
            protocol: ListenProtocol::Http,
        }],
        routes: vec![Route {
            id: RouteId("web".into()),
            listener: ListenerId("http".into()),
            host: "a.example.org".into(),
            path_prefix: "/".into(),
            action: RouteAction::Forward("pool".into()),
        }],
        pools: vec![UpstreamPool {
            id: PoolId("pool".into()),
            scheme: Scheme::Http,
            lb_policy: Default::default(),
            upstreams: vec![Upstream {
                host: upstream.ip().to_string(),
                port: upstream.port(),
                weight: 1,
            }],
            health_check: None,
        }],
        ..Default::default()
    };
    let timeouts = TimeoutsConfig {
        request_header: Duration::from_millis(200),
        client_idle: Duration::from_millis(200),
        ..Default::default()
    };
    let shared = build_shared_with(timeouts, LimitsConfig::default());
    let (proxy_addr, _tx) = start_proxy(&cfg, shared).await;

    let (status, body) = http_get(proxy_addr, "a.example.org", "/").await;

    assert_eq!(status, 200, "body: {body}");
}

#[tokio::test]
async fn rejects_request_headers_larger_than_max_header_bytes() {
    let limits = LimitsConfig {
        max_header_bytes: 8192,
        ..Default::default()
    };
    let shared = build_shared_with(TimeoutsConfig::default(), limits);
    let (proxy_addr, _tx) = start_proxy(&fixed_response_config(), shared).await;

    // A request head that fills the whole limit without ever ending. Sending
    // exactly the limit (and no more) keeps the close clean: the server has
    // nothing left unread, so the client sees the response, not a reset.
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let prefix = "GET / HTTP/1.1\r\nhost: a.example.org\r\nx-padding: ";
    let request = format!("{prefix}{}", "a".repeat(8192 - prefix.len()));
    stream.write_all(request.as_bytes()).await.unwrap();
    let received = read_until_closed(&mut stream).await;

    assert!(received.starts_with("HTTP/1.1 431"), "{received}");
}

/// A plaintext listener on an explicit loopback port.
fn http_listener(id: &str, port: u16) -> Listener {
    Listener {
        id: ListenerId(id.into()),
        address: "127.0.0.1".parse().unwrap(),
        port,
        protocol: ListenProtocol::Http,
    }
}

/// A loopback port that was free a moment ago.
fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    probe.local_addr().unwrap().port()
}

/// Whether something accepts connections on `addr`, waiting up to a few
/// seconds for it to reach the `expected` state.
async fn accepts_connections(addr: SocketAddr, expected: bool) -> bool {
    for _ in 0..100 {
        if TcpStream::connect(addr).await.is_ok() == expected {
            return expected;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    !expected
}

#[tokio::test]
async fn reconcile_binds_added_listener() {
    let mut cfg = fixed_response_config();
    let (listeners, _tx) = start_listeners(&cfg, build_shared());

    // The fixed-response route is bound to the "http" listener, so the added
    // listener is given a route of its own.
    let added = http_listener("added", free_port());
    cfg.listeners.push(added.clone());
    reconcile(&listeners, &cfg.listeners);

    let addr = listeners.local_addr(&added.id).unwrap();
    assert!(accepts_connections(addr, true).await);
}

#[tokio::test]
async fn reconcile_stops_removed_listener() {
    let mut cfg = fixed_response_config();
    let removed = http_listener("removed", free_port());
    cfg.listeners.push(removed.clone());
    let (listeners, _tx) = start_listeners(&cfg, build_shared());
    let addr = listeners.local_addr(&removed.id).unwrap();
    assert!(accepts_connections(addr, true).await);

    cfg.listeners.pop();
    reconcile(&listeners, &cfg.listeners);

    assert!(!accepts_connections(addr, false).await);
    assert_eq!(listeners.local_addr(&removed.id), None);
}

#[tokio::test]
async fn reconcile_keeps_unchanged_listener_bound() {
    let cfg = fixed_response_config();
    let (listeners, _tx) = start_listeners(&cfg, build_shared());
    let id = &cfg.listeners[0].id;
    let before = listeners.local_addr(id).unwrap();

    reconcile(&listeners, &cfg.listeners);

    // The config asks for port 0, so a rebind would land on another port.
    assert_eq!(listeners.local_addr(id), Some(before));
    let (status, _) = http_get(before, "a.example.org", "/").await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn stage_fails_without_side_effects_when_address_is_taken() {
    let cfg = fixed_response_config();
    let (listeners, _tx) = start_listeners(&cfg, build_shared());
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let unbindable = http_listener("unbindable", taken.local_addr().unwrap().port());

    let staged = listeners.stage(&[cfg.listeners[0].clone(), unbindable.clone()]);

    assert!(staged.is_err());
    assert_eq!(listeners.local_addr(&unbindable.id), None);
    let addr = listeners.local_addr(&cfg.listeners[0].id).unwrap();
    assert!(accepts_connections(addr, true).await);
}

/// A body fed frame by frame through a channel, so a test controls exactly
/// when each message (and the trailers) of a stream is sent.
struct ChannelBody(tokio::sync::mpsc::Receiver<hyper::body::Frame<Bytes>>);

impl hyper::body::Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|frame| frame.map(Ok))
    }
}

/// Spawn a cleartext HTTP/2 upstream that behaves like a gRPC echo service:
/// every request message is sent straight back, and the call ends with
/// `grpc-status: 0` trailers. The `x-seen-te` response header reports the
/// `te` request header the upstream received.
async fn spawn_grpc_upstream() -> SocketAddr {
    use hyper::body::Frame;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let seen_te = req
                        .headers()
                        .get("te")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("none")
                        .to_string();
                    let (tx, rx) = tokio::sync::mpsc::channel(1);
                    tokio::spawn(async move {
                        let mut messages = req.into_body();
                        while let Some(Ok(frame)) = messages.frame().await {
                            if let Ok(data) = frame.into_data() {
                                let _ = tx.send(Frame::data(data)).await;
                            }
                        }
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert("grpc-status", "0".parse().unwrap());
                        let _ = tx.send(Frame::trailers(trailers)).await;
                    });
                    let resp = Response::builder()
                        .header("content-type", "application/grpc")
                        .header("x-seen-te", seen_te)
                        .body(ChannelBody(rx))
                        .unwrap();
                    Ok::<_, Infallible>(resp)
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    addr
}

/// A plaintext listener routing everything to one cleartext-HTTP/2 backend.
fn grpc_config(upstream: SocketAddr) -> DynamicConfig {
    DynamicConfig {
        listeners: vec![Listener {
            id: ListenerId("grpc".into()),
            address: "127.0.0.1".parse().unwrap(),
            port: 0,
            protocol: ListenProtocol::Http,
        }],
        routes: vec![Route {
            id: RouteId("grpc".into()),
            listener: ListenerId("grpc".into()),
            host: "*".into(),
            path_prefix: "/".into(),
            action: RouteAction::Forward("grpc".into()),
        }],
        pools: vec![UpstreamPool {
            id: PoolId("grpc".into()),
            scheme: Scheme::H2c,
            lb_policy: Default::default(),
            upstreams: vec![Upstream {
                host: upstream.ip().to_string(),
                port: upstream.port(),
                weight: 1,
            }],
            health_check: None,
        }],
        ..Default::default()
    }
}

/// An open gRPC-style call through the proxy: the sending half of the
/// request stream and the response.
struct GrpcCall {
    request: tokio::sync::mpsc::Sender<hyper::body::Frame<Bytes>>,
    response: Response<Incoming>,
}

impl GrpcCall {
    /// Open a call over cleartext HTTP/2, as a gRPC client would.
    async fn open(proxy: SocketAddr) -> GrpcCall {
        let stream = TcpStream::connect(proxy).await.unwrap();
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let (request, rx) = tokio::sync::mpsc::channel(1);
        let req = Request::builder()
            .method("POST")
            .uri("http://grpc.example.org/echo.Echo/Stream")
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(ChannelBody(rx))
            .unwrap();
        let response = sender.send_request(req).await.unwrap();
        GrpcCall { request, response }
    }

    async fn send(&self, message: &'static str) {
        let frame = hyper::body::Frame::data(Bytes::from(message));
        self.request.send(frame).await.unwrap();
    }

    /// The next frame of the response, failing the test if none arrives.
    async fn next_frame(&mut self) -> hyper::body::Frame<Bytes> {
        tokio::time::timeout(Duration::from_secs(5), self.response.body_mut().frame())
            .await
            .expect("a response frame should arrive")
            .expect("the response stream should not have ended")
            .unwrap()
    }

    /// End the request stream and return the trailers that close the call,
    /// which is where gRPC carries the call's status.
    async fn finish(mut self) -> http::HeaderMap {
        let (closed, _) = tokio::sync::mpsc::channel(1);
        drop(std::mem::replace(&mut self.request, closed));
        // HTTP/2 may end the request with an empty DATA frame, which the echo
        // upstream sends back before the trailers.
        loop {
            if let Ok(trailers) = self.next_frame().await.into_trailers() {
                return trailers;
            }
        }
    }
}

#[tokio::test]
async fn relays_grpc_call_with_trailers_to_h2c_upstream() {
    let upstream = spawn_grpc_upstream().await;
    let (proxy, _tx) = start_proxy(&grpc_config(upstream), build_shared()).await;

    let mut call = GrpcCall::open(proxy).await;
    call.send("ping").await;
    assert_eq!(call.response.status(), 200);
    assert_eq!(call.next_frame().await.into_data().unwrap(), "ping");
    let trailers = call.finish().await;

    assert_eq!(trailers["grpc-status"], "0");
}

/// gRPC servers use `te: trailers` to detect proxies that cannot relay
/// trailers, and reject calls that arrive without it.
#[tokio::test]
async fn forwards_te_trailers_to_grpc_upstream() {
    let upstream = spawn_grpc_upstream().await;
    let (proxy, _tx) = start_proxy(&grpc_config(upstream), build_shared()).await;

    let call = GrpcCall::open(proxy).await;

    assert_eq!(call.response.headers()["x-seen-te"], "trailers");
}

#[tokio::test]
async fn relays_grpc_stream_message_by_message() {
    let upstream = spawn_grpc_upstream().await;
    let (proxy, _tx) = start_proxy(&grpc_config(upstream), build_shared()).await;

    // Each reply is awaited before the next message is sent, with the request
    // stream still open: anything buffered until end-of-stream would stall.
    let mut call = GrpcCall::open(proxy).await;
    call.send("one").await;
    assert_eq!(call.next_frame().await.into_data().unwrap(), "one");
    call.send("two").await;
    assert_eq!(call.next_frame().await.into_data().unwrap(), "two");
}

/// The JSON log lines emitted on this thread while the guard is alive.
#[derive(Clone, Default)]
struct CapturedLogs(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLogs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl CapturedLogs {
    /// Capture logs the way the node emits them (JSON). The proxy and the
    /// test share one thread, so a thread-default subscriber sees them all.
    fn start() -> (CapturedLogs, tracing::subscriber::DefaultGuard) {
        let logs = CapturedLogs::default();
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(move || writer.clone())
            .finish();
        (logs, tracing::subscriber::set_default(subscriber))
    }

    /// The fields of the single access-log event of the test, waiting for it
    /// to be emitted.
    async fn access_event(&self) -> serde_json::Value {
        self.single_event_of("gfe::access").await
    }

    /// The fields of the single connection-log event of the test, waiting
    /// for it to be emitted.
    async fn connection_event(&self) -> serde_json::Value {
        self.single_event_of("gfe::conn").await
    }

    async fn single_event_of(&self, target: &str) -> serde_json::Value {
        for _ in 0..250 {
            let events = self.events_of(target);
            if let [event] = events.as_slice() {
                return event.clone();
            }
            assert!(events.len() < 2, "more than one {target} event: {events:?}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("no {target} event was logged");
    }

    fn events_of(&self, target: &str) -> Vec<serde_json::Value> {
        let raw = self.0.lock().unwrap().clone();
        String::from_utf8_lossy(&raw)
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|event| event["target"] == target)
            .map(|event| event["fields"].clone())
            .collect()
    }
}

/// A plaintext listener forwarding `a.example.org` to one HTTP/1.1 backend.
fn forwarding_config(upstream: SocketAddr) -> DynamicConfig {
    DynamicConfig {
        listeners: vec![Listener {
            id: ListenerId("http".into()),
            address: "127.0.0.1".parse().unwrap(),
            port: 0,
            protocol: ListenProtocol::Http,
        }],
        routes: vec![Route {
            id: RouteId("web".into()),
            listener: ListenerId("http".into()),
            host: "a.example.org".into(),
            path_prefix: "/".into(),
            action: RouteAction::Forward("pool".into()),
        }],
        pools: vec![UpstreamPool {
            id: PoolId("pool".into()),
            scheme: Scheme::Http,
            lb_policy: Default::default(),
            upstreams: vec![Upstream {
                host: upstream.ip().to_string(),
                port: upstream.port(),
                weight: 1,
            }],
            health_check: None,
        }],
        ..Default::default()
    }
}

#[tokio::test]
async fn access_log_describes_a_proxied_request() {
    let (logs, _guard) = CapturedLogs::start();
    let upstream = spawn_upstream().await;
    let (proxy, _tx) = start_proxy(&forwarding_config(upstream), build_shared()).await;

    let (_, body) = http_get(proxy, "a.example.org", "/some/path").await;
    let event = logs.access_event().await;

    assert_eq!(event["status"], 200);
    assert_eq!(event["method"], "GET");
    assert_eq!(event["host"], "a.example.org");
    assert_eq!(event["path"], "/some/path");
    assert_eq!(event["http_version"], "HTTP/1.1");
    assert_eq!(event["client"], "127.0.0.1");
    assert_eq!(event["route"], "web");
    assert_eq!(event["pool"], "pool");
    assert_eq!(event["backend"], upstream.to_string());
    assert_eq!(event["attempts"], 1);
    assert_eq!(event["termination"], "complete");
    assert_eq!(event["response_bytes"], body.len());
    assert!(event["duration_ms"].as_f64().unwrap() > 0.0, "{event}");
    assert!(event["upstream_ttfb_ms"].as_f64().unwrap() > 0.0, "{event}");
}

#[tokio::test]
async fn access_log_and_metrics_count_body_bytes() {
    let (logs, _guard) = CapturedLogs::start();
    let upstream = spawn_upstream().await;
    let shared = build_shared();
    let (proxy, _tx) = start_proxy(&forwarding_config(upstream), shared.clone()).await;

    let stream = TcpStream::connect(proxy).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method("POST")
        .uri("/upload")
        .header("host", "a.example.org")
        .body(Full::new(Bytes::from(vec![b'x'; 1000])))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let event = logs.access_event().await;

    assert_eq!(event["request_bytes"], 1000);
    assert_eq!(event["response_bytes"], body.len());
    let labels = r#"{listener="http",host="a.example.org",route="web"}"#;
    let metrics = shared.metrics.encode();
    assert!(
        metrics.contains(&format!("gfe_request_body_bytes_total{labels} 1000")),
        "{metrics}"
    );
    assert!(
        metrics.contains(&format!(
            "gfe_response_body_bytes_total{labels} {}",
            body.len()
        )),
        "{metrics}"
    );
    assert!(metrics.contains("gfe_requests_in_flight 0"), "{metrics}");
}

/// A client that gives up while GFE is still waiting for the upstream never
/// receives a status. It is logged as 499, the convention nginx established.
#[tokio::test]
async fn logs_request_abandoned_before_the_response_as_499() {
    let (logs, _guard) = CapturedLogs::start();
    let upstream = spawn_upstream_answering_after(Duration::from_secs(3)).await;
    let shared = build_shared();
    let (proxy, _tx) = start_proxy(&forwarding_config(upstream), shared.clone()).await;

    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(b"GET /slow HTTP/1.1\r\nhost: a.example.org\r\n\r\n")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(stream);
    let event = logs.access_event().await;

    assert_eq!(event["status"], 499);
    assert_eq!(event["termination"], "client_abort");
    assert_eq!(event["path"], "/slow");
    let metrics = shared.metrics.encode();
    assert!(
        metrics.contains(
            r#"gfe_requests_aborted_total{listener="http",host="a.example.org",route="web",by="client"} 1"#
        ),
        "{metrics}"
    );
}

#[tokio::test]
async fn logs_client_abort_in_the_middle_of_a_response() {
    let (logs, _guard) = CapturedLogs::start();
    let upstream = spawn_grpc_upstream().await;
    let (proxy, _tx) = start_proxy(&grpc_config(upstream), build_shared()).await;

    // The stream is open and has delivered a message when the client leaves.
    let mut call = GrpcCall::open(proxy).await;
    call.send("one").await;
    assert_eq!(call.next_frame().await.into_data().unwrap(), "one");
    drop(call);
    let event = logs.access_event().await;

    assert_eq!(event["status"], 200);
    assert_eq!(event["termination"], "client_abort");
    assert_eq!(event["response_bytes"], 3);
    assert_eq!(event["request_bytes"], 3);
}

/// One HTTPS listener with a self-signed certificate for `secure.example.org`
/// answering every request with a fixed `200 ok`. Returns the config and the
/// certificate file for clients to trust.
fn tls_fixed_response_config() -> (DynamicConfig, std::path::PathBuf) {
    let (cert_file, key_file) = self_signed_files("secure.example.org");
    let mut cfg = fixed_response_config();
    cfg.listeners[0].protocol = ListenProtocol::Https;
    cfg.certificates = vec![CertEntry {
        sni: vec!["secure.example.org".into()],
        default: false,
        cert_file: cert_file.clone(),
        key_file,
    }];
    (cfg, cert_file)
}

#[tokio::test]
async fn connection_log_reports_a_finished_connection() {
    let (logs, _guard) = CapturedLogs::start();
    let shared = build_shared();
    let (proxy, _tx) = start_proxy(&fixed_response_config(), shared.clone()).await;

    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let request = "GET / HTTP/1.1\r\nhost: a.example.org\r\nconnection: close\r\n\r\n";
    stream.write_all(request.as_bytes()).await.unwrap();
    let response = read_until_closed(&mut stream).await;
    let event = logs.connection_event().await;

    assert_eq!(event["reason"], "closed");
    assert_eq!(event["listener"], "http");
    assert_eq!(event["client"], "127.0.0.1");
    assert_eq!(event["requests"], 1);
    assert_eq!(event["bytes_in"], request.len());
    assert_eq!(event["bytes_out"], response.len());
    assert!(event["duration_ms"].as_f64().unwrap() > 0.0, "{event}");
    let metrics = shared.metrics.encode();
    for expected in [
        r#"gfe_connections_closed_total{listener="http",reason="closed"} 1"#.to_string(),
        format!(r#"gfe_bytes_in_total{{listener="http"}} {}"#, request.len()),
        format!(
            r#"gfe_bytes_out_total{{listener="http"}} {}"#,
            response.len()
        ),
        "gfe_connections_active 0".to_string(),
    ] {
        assert!(
            metrics.contains(&expected),
            "missing {expected} in:\n{metrics}"
        );
    }
}

#[tokio::test]
async fn connection_and_access_logs_report_tls_parameters() {
    let (logs, _guard) = CapturedLogs::start();
    let (cfg, cert_file) = tls_fixed_response_config();
    let shared = build_shared();
    let (proxy, _tx) = start_proxy(&cfg, shared.clone()).await;

    https_get(proxy, &cert_file, "secure.example.org").await;
    let connection = logs.connection_event().await;
    let access = logs.access_event().await;

    assert_eq!(connection["tls_version"], "TLSv1.3");
    assert_eq!(connection["alpn"], "http/1.1");
    assert_eq!(connection["sni"], "secure.example.org");
    assert_eq!(connection["tls_resumed"], false);
    assert!(connection["tls_handshake_ms"].as_f64().unwrap() > 0.0);
    let cipher = connection["tls_cipher"].as_str().unwrap();
    assert!(cipher.starts_with("TLS13_"), "{cipher}");
    assert_eq!(access["tls_version"], "TLSv1.3");
    assert_eq!(access["tls_cipher"], cipher);
    let metrics = shared.metrics.encode();
    let expected = format!(
        r#"gfe_tls_connections_total{{version="TLSv1.3",cipher="{cipher}",alpn="http/1.1",resumed="false"}} 1"#
    );
    assert!(
        metrics.contains(&expected),
        "missing {expected} in:\n{metrics}"
    );
}

#[tokio::test]
async fn connection_log_reports_why_a_silent_connection_was_closed() {
    let (logs, _guard) = CapturedLogs::start();
    let timeouts = TimeoutsConfig {
        request_header: Duration::from_millis(200),
        ..Default::default()
    };
    let shared = build_shared_with(timeouts, LimitsConfig::default());
    let (proxy, _tx) = start_proxy(&fixed_response_config(), shared).await;

    let mut stream = TcpStream::connect(proxy).await.unwrap();
    read_until_closed(&mut stream).await;
    let event = logs.connection_event().await;

    assert_eq!(event["reason"], "header_timeout");
    assert_eq!(event["requests"], 0);
}

/// Plain HTTP sent to an HTTPS listener: the most common "broken handshake".
#[tokio::test]
async fn failed_tls_handshake_is_logged_and_counted_by_reason() {
    let (logs, _guard) = CapturedLogs::start();
    let (cfg, _cert_file) = tls_fixed_response_config();
    let shared = build_shared();
    let (proxy, _tx) = start_proxy(&cfg, shared.clone()).await;

    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nhost: secure.example.org\r\n\r\n")
        .await
        .unwrap();
    let mut discarded = Vec::new();
    let _ = stream.read_to_end(&mut discarded).await;
    let event = logs.connection_event().await;

    assert_eq!(event["reason"], "tls_handshake_failed");
    assert_eq!(event["tls_error"], "invalid_message");
    let metrics = shared.metrics.encode();
    let expected = r#"gfe_tls_handshake_failures_total{reason="invalid_message"} 1"#;
    assert!(
        metrics.contains(expected),
        "missing {expected} in:\n{metrics}"
    );
}
