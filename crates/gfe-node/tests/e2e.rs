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
    let (listeners, tx) = listener_set(cfg, shared);
    reconcile(&listeners, &cfg.listeners);
    (listeners, tx)
}

/// Apply `cfg`, but leave its listeners to be started by the caller; returns
/// an empty listener set and the shutdown sender.
fn listener_set(
    cfg: &DynamicConfig,
    shared: Arc<ProxyShared>,
) -> (ListenerSet, watch::Sender<bool>) {
    gfe_config::apply(&shared, cfg).expect("apply config");
    let server_config = Arc::new(
        gfe_tls::server_config(shared.resolver.clone(), gfe_types::MinVersion::Tls12).unwrap(),
    );
    let (tx, rx) = watch::channel(false);
    (ListenerSet::new(shared, server_config, rx), tx)
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
        // The shortest interval validation accepts.
        interval: Duration::from_millis(100),
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

/// [`fixed_response_config`] with its one route restricted to `host`.
fn fixed_response_config_for(host: &str) -> DynamicConfig {
    let mut cfg = fixed_response_config();
    cfg.routes[0].host = host.into();
    cfg
}

#[tokio::test]
async fn wildcard_route_matches_only_subdomains_of_its_suffix() {
    let shared = build_shared();
    let (proxy_addr, _tx) = start_proxy(&fixed_response_config_for("*.example.org"), shared).await;

    let (subdomain, _) = http_get(proxy_addr, "api.example.org", "/").await;
    let (lookalike, _) = http_get(proxy_addr, "fooexample.org", "/").await;

    assert_eq!(subdomain, 200);
    assert_eq!(lookalike, 404);
}

/// Send `request` (which should ask for `connection: close`) on a fresh
/// connection and return everything the proxy answers.
async fn raw_exchange(proxy: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    read_until_closed(&mut stream).await
}

#[tokio::test]
async fn answers_400_when_the_target_and_host_header_disagree() {
    let (logs, _guard) = CapturedLogs::start();
    let (proxy, _tx) = start_proxy(&fixed_response_config(), build_shared()).await;

    let response = raw_exchange(
        proxy,
        "GET http://public.example.org/ HTTP/1.1\r\nhost: internal.example.org\r\n\
         connection: close\r\n\r\n",
    )
    .await;
    let event = logs.access_event().await;

    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert_eq!(event["status"], 400);
    assert_eq!(event["error"], "host_conflict");
}

#[tokio::test]
async fn serves_absolute_form_target_that_agrees_with_the_host_header() {
    let (proxy, _tx) = start_proxy(&fixed_response_config(), build_shared()).await;

    let response = raw_exchange(
        proxy,
        "GET http://Public.example.org:80/ HTTP/1.1\r\nhost: public.example.org\r\n\
         connection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}

#[tokio::test]
async fn answers_400_to_a_cleartext_request_without_a_host() {
    let (logs, _guard) = CapturedLogs::start();
    let (proxy, _tx) = start_proxy(&fixed_response_config(), build_shared()).await;

    let response = raw_exchange(proxy, "GET / HTTP/1.1\r\nconnection: close\r\n\r\n").await;
    let event = logs.access_event().await;

    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert_eq!(event["error"], "host_missing");
}

/// An HTTPS listener answering every request with a fixed `200 ok`, with one
/// certificate for `a.example.org` and `b.example.org` and another for
/// `c.example.org`. Returns the config and the first certificate's file.
fn tls_two_certificates_config() -> (DynamicConfig, std::path::PathBuf) {
    let dir = std::env::temp_dir();
    let mut certificates = Vec::new();
    for names in [
        vec!["a.example.org", "b.example.org"],
        vec!["c.example.org"],
    ] {
        let names: Vec<String> = names.into_iter().map(String::from).collect();
        let cert = rcgen::generate_simple_self_signed(names.clone()).unwrap();
        let tag = format!("gfe-e2e-{}-coalesce-{}", std::process::id(), names[0]);
        let cert_file = dir.join(format!("{tag}.crt"));
        let key_file = dir.join(format!("{tag}.key"));
        std::fs::write(&cert_file, cert.cert.pem()).unwrap();
        std::fs::write(&key_file, cert.key_pair.serialize_pem()).unwrap();
        certificates.push(CertEntry {
            sni: names,
            default: false,
            cert_file,
            key_file,
        });
    }
    let first_cert = certificates[0].cert_file.clone();
    let mut cfg = fixed_response_config();
    cfg.listeners[0].protocol = ListenProtocol::Https;
    cfg.certificates = certificates;
    (cfg, first_cert)
}

/// The status of `GET /` over TLS (HTTP/1.1), sending `sni` in the handshake
/// and `host` in the request, as a client reusing a connection would.
async fn https_status_with_host(
    addr: SocketAddr,
    cert_file: &std::path::Path,
    sni: &str,
    host: &str,
) -> u16 {
    use tokio_rustls::TlsConnector;

    let cert_pem = std::fs::read(cert_file).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut std::io::BufReader::new(&cert_pem[..])) {
        roots.add(c.unwrap()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let domain = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
    let tls = connector.connect(domain, tcp).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::builder()
        .uri("/")
        .header("host", host)
        .body(Empty::<Bytes>::new())
        .unwrap();
    sender.send_request(req).await.unwrap().status().as_u16()
}

#[tokio::test]
async fn serves_a_host_covered_by_the_certificate_of_the_sni() {
    let (cfg, cert_file) = tls_two_certificates_config();
    let (proxy, _tx) = start_proxy(&cfg, build_shared()).await;

    let status = https_status_with_host(proxy, &cert_file, "a.example.org", "b.example.org").await;

    assert_eq!(status, 200);
}

#[tokio::test]
async fn answers_421_to_a_host_covered_by_another_certificate_than_the_sni() {
    let (logs, _guard) = CapturedLogs::start();
    let (cfg, cert_file) = tls_two_certificates_config();
    let (proxy, _tx) = start_proxy(&cfg, build_shared()).await;

    let status = https_status_with_host(proxy, &cert_file, "a.example.org", "c.example.org").await;
    let event = logs.access_event().await;

    assert_eq!(status, 421);
    assert_eq!(event["error"], "misdirected_request");
}

#[tokio::test]
async fn open_connection_follows_a_renamed_listener() {
    let shared = build_shared();
    let mut cfg = fixed_response_config();
    let (listeners, _tx) = start_listeners(&cfg, shared.clone());
    let proxy = listeners.local_addr(&cfg.listeners[0].id).unwrap();
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(KEEP_ALIVE_GET).await.unwrap();
    read_fixed_response(&mut stream).await;

    // Same address, new id, and the route follows the new id.
    cfg.listeners[0].id = ListenerId("renamed".into());
    cfg.routes[0].listener = ListenerId("renamed".into());
    gfe_config::apply(&shared, &cfg).expect("apply config");
    reconcile(&listeners, &cfg.listeners);
    stream.write_all(KEEP_ALIVE_GET).await.unwrap();
    let status_line = read_status_line(&mut stream).await;

    assert_eq!(status_line, "HTTP/1.1 200 OK");
}

/// Read the status line of the next response on a connection.
async fn read_status_line(stream: &mut TcpStream) -> String {
    let mut received = Vec::new();
    let mut byte = [0u8; 1];
    while !received.ends_with(b"\r\n") {
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte))
            .await
            .expect("a response should arrive")
            .unwrap();
        assert!(read > 0, "the connection was closed before a response");
        received.push(byte[0]);
    }
    String::from_utf8_lossy(&received).trim_end().to_string()
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

/// [`fixed_response_config`] with its listener on `addr` instead of a port
/// picked by the kernel.
fn fixed_response_config_on(addr: SocketAddr) -> DynamicConfig {
    let mut cfg = fixed_response_config();
    cfg.listeners[0].address = addr.ip();
    cfg.listeners[0].port = addr.port();
    cfg
}

#[tokio::test]
async fn listens_on_an_adopted_socket_instead_of_binding_its_address() {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    // Made before the proxy exists, this connection waits in the socket's
    // queue: it is served only if the proxy accepts on that very socket.
    let mut queued = TcpStream::connect(addr).await.unwrap();
    let cfg = fixed_response_config_on(addr);
    let (listeners, _tx) = listener_set(&cfg, build_shared());

    listeners.adopt([(addr, socket)]);
    reconcile(&listeners, &cfg.listeners);
    queued
        .write_all(b"GET / HTTP/1.1\r\nhost: a.example.org\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_until_closed(&mut queued).await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}

#[tokio::test]
async fn closes_an_adopted_socket_that_no_listener_is_configured_on() {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let cfg = fixed_response_config();
    let (listeners, _tx) = listener_set(&cfg, build_shared());

    listeners.adopt([(addr, socket)]);
    reconcile(&listeners, &cfg.listeners);

    assert!(!accepts_connections(addr, false).await);
}

#[cfg(unix)]
#[tokio::test]
async fn lends_its_sockets_which_outlive_it() {
    let cfg = fixed_response_config();
    let shared = build_shared();
    let (listeners, shutdown) = start_listeners(&cfg, shared.clone());
    let addr = listeners.local_addr(&cfg.listeners[0].id).unwrap();

    let mut lent = listeners.sockets().unwrap();
    drain(&shared, &shutdown);
    listeners.serve_until_drained().await;
    let (configured_on, socket) = lent.pop().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    let (_, peer) = socket.accept().unwrap();

    // Lent under the address its listener is configured on (port 0 here),
    // which is what a successor looks it up by.
    assert_eq!(configured_on, "127.0.0.1:0".parse().unwrap());
    assert_eq!(peer, client.local_addr().unwrap());
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
    spawn_grpc_upstream_answering_after(Duration::ZERO).await
}

/// Like [`spawn_grpc_upstream`], but the response (headers included) only
/// starts after `delay`: a stream that has nothing to say yet.
async fn spawn_grpc_upstream_answering_after(delay: Duration) -> SocketAddr {
    use hyper::body::Frame;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| async move {
                    tokio::time::sleep(delay).await;
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

#[tokio::test]
async fn access_log_and_metrics_report_the_grpc_status() {
    let (logs, _guard) = CapturedLogs::start();
    let upstream = spawn_grpc_upstream().await;
    let shared = build_shared();
    let (proxy, _tx) = start_proxy(&grpc_config(upstream), shared.clone()).await;

    let mut call = GrpcCall::open(proxy).await;
    call.send("ping").await;
    call.next_frame().await;
    call.finish().await;
    let event = logs.access_event().await;

    assert_eq!(event["grpc_status"], 0);
    assert_eq!(event["termination"], "complete");
    let metrics = shared.metrics.encode();
    let expected =
        r#"gfe_grpc_responses_total{listener="grpc",host="*",route="grpc",grpc_status="0"} 1"#;
    assert!(
        metrics.contains(expected),
        "missing {expected} in:\n{metrics}"
    );
}

#[tokio::test]
async fn reports_why_the_upstream_could_not_be_reached() {
    let (logs, _guard) = CapturedLogs::start();
    // Bind and drop: nothing listens on the port, so connecting is refused.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = closed.local_addr().unwrap();
    drop(closed);
    let shared = build_shared();
    let (proxy, _tx) = start_proxy(&forwarding_config(dead), shared.clone()).await;

    let (status, _) = http_get(proxy, "a.example.org", "/").await;
    let event = logs.access_event().await;

    assert_eq!(status, 502);
    assert_eq!(event["error"], "upstream_connect_refused");
    // A bodyless GET is retried once, here against the only backend there is.
    assert_eq!(event["attempts"], 2);
    let metrics = shared.metrics.encode();
    for expected in [
        format!(
            r#"gfe_upstream_errors_total{{pool="pool",backend="{dead}",kind="connect_refused"}} 2"#
        ),
        r#"gfe_upstream_retries_total{pool="pool"} 1"#.to_string(),
        format!(r#"gfe_upstream_requests_in_flight{{pool="pool",backend="{dead}"}} 0"#),
    ] {
        assert!(
            metrics.contains(&expected),
            "missing {expected} in:\n{metrics}"
        );
    }
}

/// A backend is busy with a request until its response has been relayed to
/// the end, not merely until the response headers arrive.
#[tokio::test]
async fn backend_stays_in_flight_for_the_whole_response() {
    let (logs, _guard) = CapturedLogs::start();
    let upstream = spawn_grpc_upstream().await;
    let shared = build_shared();
    let (proxy, _tx) = start_proxy(&grpc_config(upstream), shared.clone()).await;
    let in_flight = |n: u8| {
        format!(r#"gfe_upstream_requests_in_flight{{pool="grpc",backend="{upstream}"}} {n}"#)
    };

    let mut call = GrpcCall::open(proxy).await;
    call.send("one").await;
    call.next_frame().await;
    let during = shared.metrics.encode();
    call.finish().await;
    logs.access_event().await;
    let after = shared.metrics.encode();

    assert!(during.contains(&in_flight(1)), "{during}");
    assert!(after.contains(&in_flight(0)), "{after}");
}

/// Spawn a mock upstream that reads the whole request body before answering
/// with its length, as an upload endpoint would.
async fn spawn_upload_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let received = req.into_body().collect().await.unwrap().to_bytes();
                    let body = format!("received {}", received.len());
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    addr
}

/// Shared state whose backends must start responding within `first_byte`.
fn build_shared_with_first_byte(first_byte: Duration) -> Arc<ProxyShared> {
    let timeouts = TimeoutsConfig {
        upstream_first_byte: first_byte,
        ..Default::default()
    };
    build_shared_with(timeouts, LimitsConfig::default())
}

#[tokio::test]
async fn gives_up_on_a_backend_silent_for_upstream_first_byte() {
    let (logs, _guard) = CapturedLogs::start();
    let upstream = spawn_upstream_answering_after(Duration::from_secs(5)).await;
    let shared = build_shared_with_first_byte(Duration::from_millis(200));
    let (proxy, _tx) = start_proxy(&forwarding_config(upstream), shared).await;

    let started = std::time::Instant::now();
    let (status, _) = http_get(proxy, "a.example.org", "/").await;
    let event = logs.access_event().await;

    assert_eq!(status, 504);
    assert_eq!(event["error"], "upstream_timeout");
    // Well before the 60s `request_total` that used to be the only bound.
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn upload_slower_than_upstream_first_byte_succeeds_while_it_progresses() {
    let upstream = spawn_upload_upstream().await;
    let shared = build_shared_with_first_byte(Duration::from_millis(300));
    let (proxy, _tx) = start_proxy(&forwarding_config(upstream), shared).await;

    // 10 bytes every 100 ms: one second in total, three times the timeout.
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let head = "POST /upload HTTP/1.1\r\nhost: a.example.org\r\ncontent-length: 100\r\nconnection: close\r\n\r\n";
    stream.write_all(head.as_bytes()).await.unwrap();
    for _ in 0..10 {
        stream.write_all(b"0123456789").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let response = read_until_closed(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("received 100"), "{response}");
}

/// When the upload itself stalls, the client is the one at fault: it gets a
/// 408 and the backend is not counted as having timed out.
#[tokio::test]
async fn stalled_upload_is_answered_with_408() {
    let (logs, _guard) = CapturedLogs::start();
    let upstream = spawn_upload_upstream().await;
    let shared = build_shared_with_first_byte(Duration::from_millis(200));
    let (proxy, _tx) = start_proxy(&forwarding_config(upstream), shared.clone()).await;

    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let head = "POST /upload HTTP/1.1\r\nhost: a.example.org\r\ncontent-length: 100\r\n\r\n";
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(b"0123456789").await.unwrap();
    let response = read_until_closed(&mut stream).await;
    let event = logs.access_event().await;

    assert!(response.starts_with("HTTP/1.1 408"), "{response}");
    assert_eq!(event["error"], "request_body_timeout");
    let metrics = shared.metrics.encode();
    assert!(!metrics.contains(r#"kind="timeout""#), "{metrics}");
}

#[tokio::test]
async fn answers_503_at_the_upstream_connection_limit() {
    let (logs, _guard) = CapturedLogs::start();
    let upstream = spawn_upstream_answering_after(Duration::from_millis(400)).await;
    let client = UpstreamClient::with_options(gfe_upstream::UpstreamClientOptions {
        max_connections: Some(1),
        ..Default::default()
    })
    .unwrap();
    let shared = Arc::new(ProxyShared::new(
        client,
        Arc::new(GfeMetrics::new()),
        LimitsConfig::default(),
        TimeoutsConfig::default(),
        TlsConfig::default(),
    ));
    let (proxy, _tx) = start_proxy(&forwarding_config(upstream), shared.clone()).await;

    // The first request holds the only upstream connection the node may open.
    let first = tokio::spawn(async move { http_get(proxy, "a.example.org", "/first").await });
    tokio::time::sleep(Duration::from_millis(150)).await;
    let (second_status, _) = http_get(proxy, "a.example.org", "/second").await;
    let (first_status, _) = first.await.unwrap();

    assert_eq!(first_status, 200);
    assert_eq!(second_status, 503);
    let refused = logs
        .events_of("gfe::access")
        .into_iter()
        .find(|event| event["path"] == "/second")
        .expect("the refused request is logged");
    assert_eq!(refused["error"], "upstream_connection_limit");
    // A node-wide limit is not something another backend selection can fix.
    assert_eq!(refused["attempts"], 1);
    assert_eq!(shared.upstream.open_connections(), 1);
}

/// A streaming call may legitimately have nothing to send, not even headers,
/// for a long time. It is bounded by the deadline its client sets, not by the
/// timeouts meant for request/response exchanges.
#[tokio::test]
async fn grpc_call_outlives_upstream_first_byte() {
    let upstream = spawn_grpc_upstream_answering_after(Duration::from_millis(700)).await;
    let shared = build_shared_with_first_byte(Duration::from_millis(200));
    let (proxy, _tx) = start_proxy(&grpc_config(upstream), shared).await;

    let mut call = GrpcCall::open(proxy).await;
    call.send("late").await;

    assert_eq!(call.response.status(), 200);
    assert_eq!(call.response.headers()["content-type"], "application/grpc");
    assert_eq!(call.next_frame().await.into_data().unwrap(), "late");
}

/// gRPC clients learn the outcome of a call from `grpc-status`, so when GFE
/// itself fails a call it must say so in gRPC's terms.
#[tokio::test]
async fn fails_grpc_call_to_a_dead_backend_with_grpc_status_unavailable() {
    let (logs, _guard) = CapturedLogs::start();
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = closed.local_addr().unwrap();
    drop(closed);
    let (proxy, _tx) = start_proxy(&grpc_config(dead), build_shared()).await;

    let call = GrpcCall::open(proxy).await;
    let event = logs.access_event().await;

    let headers = call.response.headers();
    assert_eq!(call.response.status(), 200);
    assert_eq!(headers["content-type"], "application/grpc");
    assert_eq!(headers["grpc-status"], "14");
    let message = headers["grpc-message"].to_str().unwrap();
    assert!(message.contains("upstream_connect_refused"), "{message}");
    assert_eq!(event["grpc_status"], 14);
    assert_eq!(event["error"], "upstream_connect_refused");
}

#[tokio::test]
async fn fails_grpc_call_without_a_route_with_grpc_status_unimplemented() {
    let upstream = spawn_grpc_upstream().await;
    let mut cfg = grpc_config(upstream);
    cfg.routes[0].host = "elsewhere.example.org".into();
    let (proxy, _tx) = start_proxy(&cfg, build_shared()).await;

    let call = GrpcCall::open(proxy).await;

    assert_eq!(call.response.status(), 200);
    assert_eq!(call.response.headers()["grpc-status"], "12");
}

/// Stands in for the kernel: every accepted connection waited 5 ms.
struct FixedAcceptQueue;

impl gfe_proxy::AcceptQueue for FixedAcceptQueue {
    fn waited(&self, _local: SocketAddr, _peer: SocketAddr) -> Option<Duration> {
        Some(Duration::from_millis(5))
    }
}

#[tokio::test]
async fn reports_how_long_a_connection_waited_to_be_accepted() {
    let (logs, _guard) = CapturedLogs::start();
    let shared = Arc::new(
        ProxyShared::new(
            UpstreamClient::new(1).unwrap(),
            Arc::new(GfeMetrics::new()),
            LimitsConfig::default(),
            TimeoutsConfig::default(),
            TlsConfig::default(),
        )
        .with_accept_queue(Arc::new(FixedAcceptQueue)),
    );
    let (proxy, _tx) = start_proxy(&fixed_response_config(), shared.clone()).await;

    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nhost: a.example.org\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    read_until_closed(&mut stream).await;
    let event = logs.connection_event().await;

    assert_eq!(event["accept_wait_ms"], 5.0);
    let metrics = shared.metrics.encode();
    let expected = r#"gfe_accept_queue_wait_seconds_count{listener="http"} 1"#;
    assert!(
        metrics.contains(expected),
        "missing {expected} in:\n{metrics}"
    );
}

#[tokio::test]
async fn connection_log_has_no_accept_wait_without_a_kernel_view() {
    let (logs, _guard) = CapturedLogs::start();
    let (proxy, _tx) = start_proxy(&fixed_response_config(), build_shared()).await;

    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nhost: a.example.org\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    read_until_closed(&mut stream).await;
    let event = logs.connection_event().await;

    assert!(event.get("accept_wait_ms").is_none(), "{event}");
}

#[tokio::test]
async fn tells_which_listener_a_local_address_belongs_to() {
    let cfg = fixed_response_config();
    let (listeners, _tx) = start_listeners(&cfg, build_shared());
    let bound = listeners.local_addr(&cfg.listeners[0].id).unwrap();
    let elsewhere = SocketAddr::new(bound.ip(), free_port());

    assert_eq!(
        listeners.listener_at(bound),
        Some(cfg.listeners[0].id.clone())
    );
    assert_eq!(listeners.listener_at(elsewhere), None);
}

/// Begin draining, as the node does when it is told to stop.
fn drain(shared: &ProxyShared, shutdown: &watch::Sender<bool>) {
    shared
        .draining
        .store(true, std::sync::atomic::Ordering::SeqCst);
    shutdown.send(true).unwrap();
}

/// A request that leaves the connection open for the next one.
const KEEP_ALIVE_GET: &[u8] = b"GET / HTTP/1.1\r\nhost: a.example.org\r\n\r\n";

/// Read one response of [`fixed_response_config`] from a connection that is
/// expected to stay open.
async fn read_fixed_response(stream: &mut TcpStream) -> String {
    let mut received = Vec::new();
    let mut chunk = [0u8; 1024];
    while !received.ends_with(b"\r\n\r\nok") {
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .expect("a response should arrive")
            .unwrap();
        assert!(
            read > 0,
            "the connection was closed in the middle of a response"
        );
        received.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8_lossy(&received).to_string()
}

#[tokio::test]
async fn draining_node_answers_one_more_request_and_closes_the_connection() {
    let shared = build_shared();
    let (proxy, shutdown) = start_proxy(&fixed_response_config(), shared.clone()).await;
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(KEEP_ALIVE_GET).await.unwrap();
    read_fixed_response(&mut stream).await;

    drain(&shared, &shutdown);
    stream.write_all(KEEP_ALIVE_GET).await.unwrap();
    let last = read_until_closed(&mut stream).await;

    assert!(last.starts_with("HTTP/1.1 200"), "{last}");
    assert!(
        last.to_ascii_lowercase().contains("connection: close"),
        "{last}"
    );
}

#[tokio::test]
async fn draining_node_finishes_the_request_in_flight_and_closes_the_connection() {
    let upstream = spawn_upstream_answering_after(Duration::from_millis(300)).await;
    let shared = build_shared();
    let (proxy, shutdown) = start_proxy(&forwarding_config(upstream), shared.clone()).await;
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(KEEP_ALIVE_GET).await.unwrap();
    // By now the request is with the backend.
    tokio::time::sleep(Duration::from_millis(100)).await;

    drain(&shared, &shutdown);
    let response = read_until_closed(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("upstream-ok"), "{response}");
}

#[tokio::test]
async fn draining_node_closes_a_connection_that_stays_idle() {
    let timeouts = TimeoutsConfig {
        drain_deadline: Duration::from_millis(400),
        ..Default::default()
    };
    let shared = build_shared_with(timeouts, LimitsConfig::default());
    let (proxy, shutdown) = start_proxy(&fixed_response_config(), shared.clone()).await;
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(KEEP_ALIVE_GET).await.unwrap();
    read_fixed_response(&mut stream).await;

    drain(&shared, &shutdown);
    let rest = read_until_closed(&mut stream).await;

    assert_eq!(rest, "");
}

#[tokio::test]
async fn draining_node_finishes_an_http2_request_and_ends_the_connection() {
    let upstream = spawn_upstream_answering_after(Duration::from_millis(300)).await;
    let shared = build_shared();
    let (proxy, shutdown) = start_proxy(&forwarding_config(upstream), shared.clone()).await;
    let stream = TcpStream::connect(proxy).await.unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();
    let connection = tokio::spawn(conn);
    // The client keeps its side open: only the node can end the connection.
    let _client = sender.clone();
    let request = Request::builder()
        .uri("http://a.example.org/")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = tokio::spawn(async move { sender.send_request(request).await });
    // By now the request is with the backend.
    tokio::time::sleep(Duration::from_millis(100)).await;

    drain(&shared, &shutdown);
    let response = response.await.unwrap().unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let ended = tokio::time::timeout(Duration::from_secs(5), connection).await;

    assert_eq!(status, 200);
    assert!(body.starts_with(b"upstream-ok"), "{body:?}");
    assert!(ended.is_ok(), "the node did not end the connection");
}

#[tokio::test]
async fn connection_log_tells_a_connection_closed_by_a_drain() {
    let (logs, _guard) = CapturedLogs::start();
    let shared = build_shared();
    let (proxy, shutdown) = start_proxy(&fixed_response_config(), shared.clone()).await;
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(KEEP_ALIVE_GET).await.unwrap();
    read_fixed_response(&mut stream).await;

    drain(&shared, &shutdown);
    stream.write_all(KEEP_ALIVE_GET).await.unwrap();
    read_until_closed(&mut stream).await;
    let event = logs.connection_event().await;

    assert_eq!(event["reason"], "drain");
}
