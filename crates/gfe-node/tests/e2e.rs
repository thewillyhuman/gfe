//! End-to-end Phase 1 integration tests: a real GFE proxy in front of a mock
//! upstream, exercised over plaintext HTTP and over TLS.

use arc_swap::ArcSwap;
use bytes::Bytes;
use gfe_metrics::GfeMetrics;
use gfe_proxy::{ProxyEngine, ProxyShared};
use gfe_router::RouteTable;
use gfe_tls::{CertStore, ChallengeStore, SniResolver};
use gfe_types::{
    CertEntry, DynamicConfig, LimitsConfig, ListenProtocol, Listener, ListenerId, PoolId, Route,
    RouteAction, RouteId, Scheme, TimeoutsConfig, TlsConfig, Upstream, UpstreamPool,
};
use gfe_upstream::{HealthMap, PoolSet, UpstreamClient};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// Spawn a mock upstream that echoes the `X-Forwarded-For` and `Host` headers
/// so tests can assert forwarding behaviour.
async fn spawn_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|req: Request<Incoming>| async move {
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
    let resolver = Arc::new(SniResolver::new(CertStore::default()));
    Arc::new(ProxyShared {
        routes: ArcSwap::from_pointee(RouteTable::default()),
        pools: ArcSwap::from_pointee(PoolSet::default()),
        resolver,
        challenges: Arc::new(ChallengeStore::new()),
        health: Arc::new(HealthMap::new(true)),
        upstream: UpstreamClient::new(16).unwrap(),
        metrics: Arc::new(GfeMetrics::new()),
        limits: LimitsConfig::default(),
        timeouts: TimeoutsConfig::default(),
        tls: TlsConfig::default(),
        draining: AtomicBool::new(false),
    })
}

/// Start a proxy serving `cfg`; returns the bound proxy address and a shutdown
/// sender plus the shared state.
async fn start_proxy(
    cfg: &DynamicConfig,
    shared: Arc<ProxyShared>,
) -> (SocketAddr, watch::Sender<bool>) {
    gfe_config::apply(&shared, cfg).expect("apply config");
    let server_config = Arc::new(
        gfe_tls::server_config(shared.resolver.clone(), gfe_types::MinVersion::Tls12).unwrap(),
    );
    let bound = ProxyEngine::bind(&cfg.listeners).await.expect("bind");
    let proxy_addr = bound[0].1.local_addr().unwrap();
    let engine = ProxyEngine::new(shared);
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move {
        engine.serve(bound, server_config, rx).await;
    });
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
    use tokio_rustls::TlsConnector;

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

    // Build a client trusting the self-signed cert.
    let cert_pem = std::fs::read(&cp).unwrap();
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

    let tcp = TcpStream::connect(proxy_addr).await.unwrap();
    let domain = rustls::pki_types::ServerName::try_from("secure.example.org").unwrap();
    let tls = connector.connect(domain, tcp).await.unwrap();
    let io = TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .uri("/")
        .header("host", "secure.example.org")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("upstream-ok"), "body: {text}");
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
    use std::time::Duration;

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
