//! What the functional tests share: a proxy serving a config, mock backends
//! and clients on hyper, certificates by rcgen, and the access log captured.
//!
//! There are two ways to run the proxy:
//!
//! - [`node::Node`] is a whole front end, as a node runs it: the edge
//!   (listeners, TLS termination, connection accounting, drain), the proxy,
//!   and the config it follows. Tests of what crosses those parts use it.
//! - [`Proxy`] is the proxy alone, served by a minimal accept loop of its
//!   own, which registers every connection the way the edge does. A test
//!   that needs "a TLS connection with SNI x" registers its connections with
//!   a [`TlsInfo`] and talks cleartext to the proxy: the proxy learns
//!   everything about a connection from its registration.

#![allow(dead_code)]

pub mod node;

use arc_swap::ArcSwap;
use bytes::Bytes;
use gfe_config::{
    CertEntry, ControlPlaneConfig, DynamicConfig, ListenProtocol, Listener, ListenerId, NodeConfig,
    NodeSection, PoolId, Route, RouteAction, RouteId, Scheme, Upstream, UpstreamPool,
};
use gfe_core::listener::{ConnInfo, Connections};
use gfe_core::proxy::{self, State};
use gfe_core::routing::RouteTable;
use gfe_observability::GfeMetrics;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use netkit_load_balancing::PoolSet;
use netkit_tls::{CertStore, TlsInfo};
use pingora_core::apps::ServerApp;
use pingora_core::protocols::GetSocketDigest;
use pingora_core::protocols::SocketDigest;
use pingora_core::protocols::l4::stream::Stream;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

// ---------------------------------------------------------------------------
// The proxy
// ---------------------------------------------------------------------------

/// A node config with every default.
pub fn node_config() -> NodeConfig {
    NodeConfig {
        node: NodeSection {
            id: "test".into(),
            loopback_vip: None,
            metrics_addr: "127.0.0.1:0".parse().unwrap(),
            worker_threads: 1,
        },
        control_plane: ControlPlaneConfig {
            config_file: "/nonexistent".into(),
            local_cache: None,
            reload_debounce: Duration::from_millis(250),
        },
        tls: Default::default(),
        limits: Default::default(),
        timeouts: Default::default(),
        upstream: Default::default(),
        ebpf: None,
        log: Default::default(),
        health_check_defaults: Default::default(),
    }
}

/// A proxy serving one listener of a config.
pub struct Proxy {
    /// Where it listens.
    pub addr: SocketAddr,
    pub state: Arc<State>,
    /// Turns `true` to have the proxy drain.
    pub shutdown: watch::Sender<bool>,
}

impl Proxy {
    /// Serve the first listener of `cfg` with a default node config.
    pub async fn start(cfg: &DynamicConfig) -> Proxy {
        Proxy::start_with(cfg, node_config(), None).await
    }

    /// Serve the first listener of `cfg` under `node`. Every connection is
    /// registered as having negotiated `tls`, though it is cleartext.
    pub async fn start_with(cfg: &DynamicConfig, node: NodeConfig, tls: Option<TlsInfo>) -> Proxy {
        let (shutdown, watching) = watch::channel(false);
        let state = State::new(
            &node,
            Arc::new(GfeMetrics::new()),
            Connections::new(),
            watching.clone(),
        )
        .expect("the node config is valid");
        state
            .resolver()
            .swap(CertStore::build(&cfg.certificates).expect("certificates load"));
        state.swap(
            RouteTable::compile(cfg),
            PoolSet::build(&cfg.pools).expect("pools build"),
        );
        let app = proxy::app(Arc::clone(&state));
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let listener = Arc::new(ArcSwap::from_pointee(cfg.listeners[0].clone()));
        let connections = Arc::clone(state.connections());
        tokio::spawn(async move {
            loop {
                let Ok((tcp, client)) = socket.accept().await else {
                    return;
                };
                let app = Arc::clone(&app);
                let conn = ConnInfo::new(client, addr, Arc::clone(&listener), tls.clone());
                let registration = connections.register(conn);
                let watching = watching.clone();
                tokio::spawn(async move {
                    let mut stream = Stream::from(tcp);
                    let digest = SocketDigest::from_raw_fd(stream.as_raw_fd());
                    stream.set_socket_digest(digest);
                    let mut next = app.process_new(Box::new(stream), &watching).await;
                    while let Some(stream) = next {
                        next = app.process_new(stream, &watching).await;
                    }
                    drop(registration);
                });
            }
        });
        Proxy {
            addr,
            state,
            shutdown,
        }
    }

    /// The metrics, as Prometheus scrapes them.
    pub fn metrics(&self) -> String {
        self.state.metrics().encode()
    }

    /// Wait until the metrics contain `line`, failing the test if they do
    /// not within a few seconds.
    pub async fn wait_for_metric(&self, line: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let metrics = self.metrics();
            if metrics.contains(line) {
                return;
            }
            assert!(Instant::now() < deadline, "missing {line} in:\n{metrics}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// What a TLS handshake that asked for `sni` settled on.
pub fn tls_info(sni: &str) -> TlsInfo {
    TlsInfo {
        sni: Some(sni.to_string()),
        version: "TLSv1.3",
        cipher: "TLS13_AES_256_GCM_SHA384".to_string(),
        alpn: Some("http/1.1".to_string()),
        resumed: false,
    }
}

// ---------------------------------------------------------------------------
// Configs
// ---------------------------------------------------------------------------

/// A plaintext listener `http` on an unbound address (the harness binds).
pub fn http_listener() -> Listener {
    Listener {
        id: ListenerId("http".into()),
        address: "127.0.0.1".parse().unwrap(),
        port: 0,
        protocol: ListenProtocol::Http,
    }
}

/// A pool `id` of `scheme` with one backend per address.
pub fn pool(id: &str, scheme: Scheme, backends: &[SocketAddr]) -> UpstreamPool {
    UpstreamPool {
        id: PoolId(id.into()),
        scheme,
        lb_policy: Default::default(),
        upstreams: backends
            .iter()
            .map(|addr| Upstream {
                host: addr.ip().to_string(),
                port: addr.port(),
                weight: 1,
            })
            .collect(),
        health_check: None,
        max_in_flight: None,
    }
}

/// A route `id` on listener `http` for `host` and `path`.
pub fn route(id: &str, host: &str, path: &str, action: RouteAction) -> Route {
    Route {
        id: RouteId(id.into()),
        listener: ListenerId("http".into()),
        host: host.into(),
        path_prefix: path.into(),
        action,
    }
}

/// A plaintext listener forwarding `a.example.org` to one HTTP/1.1 backend.
pub fn forwarding_config(upstream: SocketAddr) -> DynamicConfig {
    DynamicConfig {
        listeners: vec![http_listener()],
        routes: vec![route(
            "web",
            "a.example.org",
            "/",
            RouteAction::Forward("pool".into()),
        )],
        pools: vec![pool("pool", Scheme::Http, &[upstream])],
        ..Default::default()
    }
}

/// One plaintext listener answering every request with a fixed `200 ok`.
pub fn fixed_response_config() -> DynamicConfig {
    DynamicConfig {
        listeners: vec![http_listener()],
        routes: vec![route(
            "fixed",
            "*",
            "/",
            RouteAction::Fixed(gfe_config::FixedAction {
                status: 200,
                body: "ok".into(),
            }),
        )],
        ..Default::default()
    }
}

/// A plaintext listener routing everything to one cleartext-HTTP/2 backend.
pub fn grpc_config(upstream: SocketAddr) -> DynamicConfig {
    DynamicConfig {
        listeners: vec![http_listener()],
        routes: vec![route("grpc", "*", "/", RouteAction::Forward("grpc".into()))],
        pools: vec![pool("grpc", Scheme::H2c, &[upstream])],
        ..Default::default()
    }
}

/// An address nothing listens on: connecting to it is refused.
pub fn closed_port() -> SocketAddr {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    closed.local_addr().unwrap()
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

/// A self-signed certificate for `names`, written to files of its own.
pub fn certificate_files(names: &[&str]) -> (PathBuf, PathBuf, rcgen::CertifiedKey) {
    static FILES: AtomicUsize = AtomicUsize::new(0);
    let n = FILES.fetch_add(1, Ordering::Relaxed);
    let names: Vec<String> = names.iter().map(|name| name.to_string()).collect();
    let cert = rcgen::generate_simple_self_signed(names.clone()).unwrap();
    let dir = std::env::temp_dir();
    let tag = format!("gfe-core-test-{}-{n}", std::process::id());
    let cert_file = dir.join(format!("{tag}.crt"));
    let key_file = dir.join(format!("{tag}.key"));
    std::fs::write(&cert_file, cert.cert.pem()).unwrap();
    std::fs::write(&key_file, cert.key_pair.serialize_pem()).unwrap();
    (cert_file, key_file, cert)
}

/// A certificate entry of the dynamic config for `names`.
pub fn cert_entry(names: &[&str]) -> CertEntry {
    let (cert_file, key_file, _) = certificate_files(names);
    CertEntry {
        sni: names.iter().map(|name| name.to_string()).collect(),
        default: false,
        cert_file,
        key_file,
    }
}

// ---------------------------------------------------------------------------
// Backends
// ---------------------------------------------------------------------------

/// Serve HTTP/1.1 on a fresh port with `svc`, connection after connection.
pub async fn serve_http1<F, Fut, B>(svc: F) -> SocketAddr
where
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Response<B>> + Send + 'static,
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let svc = svc.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let response = svc(req);
                    async move { Ok::<_, Infallible>(response.await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    addr
}

/// Serve cleartext HTTP/2 (prior knowledge) on a fresh port with `svc`.
pub async fn serve_h2c<F, Fut, B>(svc: F) -> SocketAddr
where
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Response<B>> + Send + 'static,
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let svc = svc.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let response = svc(req);
                    async move { Ok::<_, Infallible>(response.await) }
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    addr
}

/// A backend that answers `upstream-ok xff=<X-Forwarded-For> host=<Host>`
/// after `delay`.
pub async fn spawn_upstream_answering_after(delay: Duration) -> SocketAddr {
    serve_http1(move |req: Request<Incoming>| async move {
        tokio::time::sleep(delay).await;
        let header = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("none")
                .to_string()
        };
        let body = format!(
            "upstream-ok xff={} host={}",
            header("x-forwarded-for"),
            header("host")
        );
        Response::new(Full::new(Bytes::from(body)))
    })
    .await
}

/// A backend that answers at once, as [`spawn_upstream_answering_after`].
pub async fn spawn_upstream() -> SocketAddr {
    spawn_upstream_answering_after(Duration::ZERO).await
}

/// A backend that reads the whole request body before answering
/// `received <length>`, as an upload endpoint would.
pub async fn spawn_upload_upstream() -> SocketAddr {
    serve_http1(|req: Request<Incoming>| async move {
        let received = req.into_body().collect().await.unwrap().to_bytes();
        Response::new(Full::new(Bytes::from(format!(
            "received {}",
            received.len()
        ))))
    })
    .await
}

/// A backend that answers every request with `200` and counts them, and the
/// connections they came on.
pub async fn spawn_counting_upstream() -> (SocketAddr, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let connections = Arc::new(AtomicUsize::new(0));
    let (counted, connected) = (Arc::clone(&requests), Arc::clone(&connections));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            connected.fetch_add(1, Ordering::SeqCst);
            let counted = Arc::clone(&counted);
            tokio::spawn(async move {
                let svc = service_fn(move |_req: Request<Incoming>| {
                    counted.fetch_add(1, Ordering::SeqCst);
                    async { Ok::<_, Infallible>(Response::new(Full::new(Bytes::from("counted")))) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    (addr, requests, connections)
}

/// A backend that accepts connections and never answers, nor closes them.
pub async fn spawn_silent_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    addr
}

/// A backend that reads a request's head and then stops reading, keeping
/// the connection open: it never takes the body.
pub async fn spawn_upstream_not_reading_the_body() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                std::future::pending::<()>().await;
                drop(stream);
            });
        }
    });
    addr
}

/// What reached a backend of a request: its HTTP version, its `Host`
/// header and the authority of its target.
pub fn describe_request(req: &Request<Incoming>) -> String {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("none");
    let authority = req.uri().authority().map_or("none", |a| a.as_str());
    format!(
        "version={:?} host={host} authority={authority}",
        req.version()
    )
}

/// A cleartext HTTP/2 backend answering every request with
/// [`describe_request`].
pub async fn spawn_h2c_describing_upstream() -> SocketAddr {
    serve_h2c(|req: Request<Incoming>| async move {
        Response::new(Full::new(Bytes::from(describe_request(&req))))
    })
    .await
}

/// How a TLS backend checks its clients.
pub enum ClientAuth {
    /// It does not ask for a client certificate.
    None,
    /// It requires one signed by this certificate (PEM).
    Required(Vec<u8>),
}

/// A TLS backend for `127.0.0.1` offering HTTP/2 and HTTP/1.1 by ALPN and
/// answering every request with [`describe_request`], or, to a gRPC call,
/// echoing it. Returns its address and the certificate (PEM) to trust it by.
pub async fn spawn_tls_upstream(name: &str, client_auth: ClientAuth) -> (SocketAddr, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap();
    let builder = match client_auth {
        ClientAuth::None => builder.with_no_client_auth(),
        ClientAuth::Required(ca_pem) => {
            let mut roots = rustls::RootCertStore::empty();
            for cert in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
                roots.add(cert.unwrap()).unwrap();
            }
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider,
            )
            .build()
            .unwrap();
            builder.with_client_cert_verifier(verifier)
        }
    };
    let mut server_cfg = builder
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .unwrap();
    server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let response = if is_grpc(&req) {
                        grpc_echo(req, Duration::ZERO).await
                    } else {
                        let body = describe_request(&req);
                        Response::new(ChannelBody::full(Bytes::from(body)))
                    };
                    Ok::<_, Infallible>(response)
                });
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    (addr, cert.cert.pem().into_bytes())
}

/// Write `pem` to a file of its own and return its path.
pub fn pem_file(pem: &[u8]) -> PathBuf {
    static FILES: AtomicUsize = AtomicUsize::new(0);
    let n = FILES.fetch_add(1, Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("gfe-core-test-{}-ca-{n}.pem", std::process::id()));
    std::fs::write(&path, pem).unwrap();
    path
}

// ---------------------------------------------------------------------------
// gRPC
// ---------------------------------------------------------------------------

/// A body fed frame by frame through a channel, so a test controls exactly
/// when each message (and the trailers) of a stream is sent.
pub struct ChannelBody(pub tokio::sync::mpsc::Receiver<Frame<Bytes>>);

impl ChannelBody {
    /// A body of one data frame.
    pub fn full(data: Bytes) -> ChannelBody {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(Frame::data(data)).unwrap();
        ChannelBody(rx)
    }
}

impl hyper::body::Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|frame| frame.map(Ok))
    }
}

/// Whether a request is a gRPC call.
pub fn is_grpc(req: &Request<Incoming>) -> bool {
    req.headers()
        .get("content-type")
        .is_some_and(|v| v.as_bytes().starts_with(b"application/grpc"))
}

/// Echo a gRPC-style call: every request message is sent straight back, and
/// the call ends with `grpc-status: 0` trailers. The response (headers
/// included) starts after `delay`. The `x-seen-te` response header reports
/// the `te` request header the backend received, and `x-described` the
/// request ([`describe_request`]).
pub async fn grpc_echo(req: Request<Incoming>, delay: Duration) -> Response<ChannelBody> {
    tokio::time::sleep(delay).await;
    let seen_te = req
        .headers()
        .get("te")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("none")
        .to_string();
    let described = describe_request(&req);
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        let mut messages = req.into_body();
        while let Some(Ok(frame)) = messages.frame().await {
            if let Ok(data) = frame.into_data()
                && tx.send(Frame::data(data)).await.is_err()
            {
                return;
            }
        }
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        let _ = tx.send(Frame::trailers(trailers)).await;
    });
    Response::builder()
        .header("content-type", "application/grpc")
        .header("x-seen-te", seen_te)
        .header("x-described", described)
        .body(ChannelBody(rx))
        .unwrap()
}

/// A cleartext HTTP/2 gRPC echo backend (see [`grpc_echo`]).
pub async fn spawn_grpc_upstream_answering_after(delay: Duration) -> SocketAddr {
    serve_h2c(move |req| grpc_echo(req, delay)).await
}

/// A cleartext HTTP/2 gRPC echo backend answering at once.
pub async fn spawn_grpc_upstream() -> SocketAddr {
    spawn_grpc_upstream_answering_after(Duration::ZERO).await
}

/// An open gRPC-style call through the proxy: the sending half of the
/// request stream and the response.
pub struct GrpcCall {
    pub request: tokio::sync::mpsc::Sender<Frame<Bytes>>,
    pub response: Response<Incoming>,
}

impl GrpcCall {
    /// Open a call over cleartext HTTP/2, as a gRPC client would.
    pub async fn open(proxy: SocketAddr) -> GrpcCall {
        let mut sender = h2_sender(proxy).await;
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

    pub async fn send(&self, message: &'static str) {
        self.request
            .send(Frame::data(Bytes::from(message)))
            .await
            .unwrap();
    }

    /// The next frame of the response, failing the test if none arrives.
    pub async fn next_frame(&mut self) -> Frame<Bytes> {
        tokio::time::timeout(Duration::from_secs(5), self.response.body_mut().frame())
            .await
            .expect("a response frame should arrive")
            .expect("the response stream should not have ended")
            .unwrap()
    }

    /// The next message of the response.
    pub async fn next_message(&mut self) -> Bytes {
        loop {
            if let Ok(data) = self.next_frame().await.into_data()
                && !data.is_empty()
            {
                return data;
            }
        }
    }

    /// End the request stream and return the trailers that close the call,
    /// which is where gRPC carries the call's status.
    pub async fn finish(mut self) -> http::HeaderMap {
        let (closed, _) = tokio::sync::mpsc::channel(1);
        drop(std::mem::replace(&mut self.request, closed));
        loop {
            if let Ok(trailers) = self.next_frame().await.into_trailers() {
                return trailers;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

/// An HTTP/2 connection to `addr` with prior knowledge.
pub async fn h2_sender(addr: SocketAddr) -> hyper::client::conn::http2::SendRequest<ChannelBody> {
    let stream = TcpStream::connect(addr).await.unwrap();
    let (sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
}

/// An HTTP/1.1 connection to `addr`.
pub async fn h1_sender<B>(addr: SocketAddr) -> hyper::client::conn::http1::SendRequest<B>
where
    B: hyper::body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let stream = TcpStream::connect(addr).await.unwrap();
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
}

/// A response, read to its end.
pub struct Answer {
    pub status: u16,
    pub headers: http::HeaderMap,
    pub body: String,
}

/// Read a response to its end.
pub async fn collect(resp: Response<Incoming>) -> Answer {
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    Answer {
        status,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    }
}

/// `GET path` for `host` over HTTP/1.1 with `headers`.
pub async fn get_with(
    addr: SocketAddr,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Answer {
    let mut sender = h1_sender(addr).await;
    let mut req = Request::builder().uri(path).header("host", host);
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    let resp = sender
        .send_request(req.body(Empty::<Bytes>::new()).unwrap())
        .await
        .unwrap();
    collect(resp).await
}

/// `GET path` for `host` over HTTP/1.1.
pub async fn http_get(addr: SocketAddr, host: &str, path: &str) -> (u16, String) {
    let answer = get_with(addr, host, path, &[]).await;
    (answer.status, answer.body)
}

/// A `method` request for `uri` with `body` over cleartext HTTP/2. The body
/// is streamed, so the request carries no `content-length`.
pub async fn h2_request(addr: SocketAddr, method: &str, uri: &str, body: &'static str) -> Answer {
    let mut sender = h2_sender(addr).await;
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .body(ChannelBody(rx))
        .unwrap();
    if !body.is_empty() {
        tokio::spawn(async move {
            let _ = tx.send(Frame::data(Bytes::from(body))).await;
        });
    } else {
        drop(tx);
    }
    let resp = sender.send_request(req).await.unwrap();
    collect(resp).await
}

/// Read until the server closes the connection, failing the test if it is
/// still open after a few seconds.
pub async fn read_until_closed(stream: &mut TcpStream) -> String {
    let mut received = Vec::new();
    let read =
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut received)).await;
    let received = String::from_utf8_lossy(&received).to_string();
    match read {
        Ok(Ok(_)) => received,
        Ok(Err(error)) => panic!("reading failed after {received:?}: {error}"),
        Err(_) => panic!("server should have closed the connection; received {received:?}"),
    }
}

/// Send `request` (which should ask for `connection: close`) on a fresh
/// connection and return everything the proxy answers.
pub async fn raw_exchange(addr: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    read_until_closed(&mut stream).await
}

// ---------------------------------------------------------------------------
// The access log
// ---------------------------------------------------------------------------

/// The JSON log lines emitted on this thread while the guard is alive.
#[derive(Clone, Default)]
pub struct CapturedLogs(Arc<std::sync::Mutex<Vec<u8>>>);

thread_local! {
    /// Where the log lines emitted on this thread go while a test captures
    /// them.
    static CAPTURING: std::cell::RefCell<Option<CapturedLogs>> =
        const { std::cell::RefCell::new(None) };
}

/// Hands each log line to the test capturing on the thread that emitted it,
/// and drops the lines of threads where no test captures.
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
pub struct Capturing;

impl Drop for Capturing {
    fn drop(&mut self) {
        CAPTURING.with(|capturing| *capturing.borrow_mut() = None);
    }
}

impl CapturedLogs {
    /// Capture logs the way the node emits them (JSON). Each test runs on a
    /// single-threaded runtime of its own, so what this thread emits is what
    /// the test's proxy logged.
    ///
    /// There is one subscriber for the whole test binary, not one per test:
    /// `tracing` caches, per callsite and for every thread, whether anybody
    /// is interested in it, and with subscribers that come and go per
    /// thread an event could be lost.
    pub fn start() -> (CapturedLogs, Capturing) {
        static SUBSCRIBER: std::sync::Once = std::sync::Once::new();
        SUBSCRIBER.call_once(|| {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter("info")
                .with_writer(|| ToCapturingTest)
                .init();
        });
        let logs = CapturedLogs::default();
        CAPTURING.with(|capturing| *capturing.borrow_mut() = Some(logs.clone()));
        (logs, Capturing)
    }

    /// The fields of the single access-log event of the test, waiting for it
    /// to be emitted.
    pub async fn access_event(&self) -> serde_json::Value {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let events = self.access_events();
            assert!(events.len() < 2, "more than one access event: {events:?}");
            if let [event] = events.as_slice() {
                return event.clone();
            }
            assert!(Instant::now() < deadline, "no access event was logged");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The access event of the request for `path`, waiting for it.
    pub async fn access_event_for(&self, path: &str) -> serde_json::Value {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let events: Vec<_> = self
                .access_events()
                .into_iter()
                .filter(|event| event["path"] == path)
                .collect();
            assert!(
                events.len() < 2,
                "more than one event for {path}: {events:?}"
            );
            if let [event] = events.as_slice() {
                return event.clone();
            }
            assert!(Instant::now() < deadline, "no access event for {path}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Every access event logged so far.
    pub fn access_events(&self) -> Vec<serde_json::Value> {
        self.events("gfe::access")
    }

    /// The fields of every event of `target` logged so far.
    pub fn events(&self, target: &str) -> Vec<serde_json::Value> {
        self.lines()
            .into_iter()
            .filter(|event| event["target"] == target)
            .map(|event| event["fields"].clone())
            .collect()
    }

    /// Every line logged so far, whole: level, target and fields.
    pub fn lines(&self) -> Vec<serde_json::Value> {
        let raw = self.0.lock().unwrap().clone();
        String::from_utf8_lossy(&raw)
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .collect()
    }

    /// The events of `target` once there are `count` of them, failing the
    /// test if there are not within a few seconds.
    pub async fn wait_for_events(&self, target: &str, count: usize) -> Vec<serde_json::Value> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let events = self.events(target);
            if events.len() >= count {
                return events;
            }
            assert!(
                Instant::now() < deadline,
                "{} {target} events, expected {count}: {events:?}",
                events.len()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Wait a moment and fail if a second access event shows up: a request
    /// is accounted for exactly once.
    pub async fn assert_no_more_than(&self, count: usize) {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let events = self.access_events();
        assert_eq!(events.len(), count, "{events:?}");
    }
}
