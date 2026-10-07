//! What the unit tests of the handler share: a node config to build a
//! [`State`] from, and a small world to run a handler in without the edge.
//!
//! A handler takes `Request<Incoming>`, which only a real connection
//! produces. [`serve`] serves a handler on a loopback port with
//! `netkit_http::server::serve`, handing it every request with a
//! [`ConnInfo`] made up for the test; clients and backends are hyper's own,
//! on loopback ports too.

use crate::edge::{ConnInfo, RequestHandler};
use crate::handler::State;
use crate::metrics::GfeMetrics;
use crate::test_logs::Captured;
pub(crate) use crate::test_logs::Capturing;
use arc_swap::ArcSwap;
use gfe_config::{
    ControlPlaneConfig, LbPolicy, ListenProtocol, Listener, ListenerId, NodeConfig, NodeSection,
    PoolId, Scheme, Upstream, UpstreamPool,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use netkit_health_checking::HealthMap;
use netkit_http::body::{self, Body, BodyExt, BoxBody, Frame, Incoming};
use netkit_http::server::{self, Options};
use netkit_http::{Bytes, Request, Response};
use netkit_load_balancing::{Pool, PoolSet};
use netkit_tls::TlsInfo;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

/// A node config with every default.
pub(crate) fn node_config() -> NodeConfig {
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

/// The state of a node configured by `config`.
pub(crate) fn state_with(config: &NodeConfig) -> Arc<State> {
    State::new(config, Arc::new(GfeMetrics::new())).unwrap()
}

/// The state of a node configured by [`node_config`].
pub(crate) fn state() -> Arc<State> {
    state_with(&node_config())
}

/// A file of its own holding `content`, in the temporary directory.
pub(crate) fn temp_file(content: &[u8]) -> PathBuf {
    // Tests run in parallel, each wants files of its own.
    static FILES: AtomicUsize = AtomicUsize::new(0);
    let n = FILES.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("gfe-handler-{}-{n}", std::process::id()));
    std::fs::write(&path, content).unwrap();
    path
}

/// Wait until the metrics of `state` expose `line`, failing the test if
/// they do not within a few seconds. A request is reported when its
/// response body is done with on the server's side, which may be a moment
/// after the client has read it.
pub(crate) async fn wait_for_metric(state: &State, line: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let exposed = state.metrics().encode();
        if exposed.contains(line) {
            return;
        }
        assert!(Instant::now() < deadline, "no {line} in {exposed}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Whether the metrics of `state` expose `line` now.
pub(crate) fn exposes(state: &State, line: &str) -> bool {
    state.metrics().encode().contains(line)
}

/// The log of one test: what was emitted on its thread while the guard is
/// alive.
#[derive(Clone)]
pub(crate) struct Logs(Captured);

impl Logs {
    /// Capture what is logged on this thread until the guard is dropped
    /// (see [`crate::test_logs`]): what the test's handler logs.
    pub(crate) fn capture() -> (Logs, Capturing) {
        let (captured, capturing) = Captured::start();
        (Logs(captured), capturing)
    }

    /// The fields of every `gfe::access` event so far.
    pub(crate) fn access_events(&self) -> Vec<serde_json::Value> {
        self.0.events("gfe::access")
    }

    /// The fields of the single `gfe::access` event of the test, waiting
    /// for it to be emitted, and failing if there is more than one.
    pub(crate) async fn access_event(&self) -> serde_json::Value {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let events = self.access_events();
            assert!(events.len() < 2, "more than one access event: {events:?}");
            if let [event] = events.as_slice() {
                return event.clone();
            }
            assert!(Instant::now() < deadline, "no access event was logged");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// The handler, served
// ---------------------------------------------------------------------------

/// What a test's connections are held to: generous, so that only the
/// handler's own timeouts show.
const SERVING: Options = Options {
    header_timeout: Duration::from_secs(10),
    idle_timeout: Duration::from_secs(10),
    keep_alive_timeout: Duration::from_secs(10),
    drain_idle_grace: Duration::from_secs(1),
    max_header_bytes: 65_536,
    max_concurrent_streams: 100,
};

/// Hands every request of one connection to a [`RequestHandler`], as the
/// edge does.
struct Edge<H> {
    handler: Arc<H>,
    conn: Arc<ConnInfo>,
}

impl<H: RequestHandler> server::Handler for Edge<H> {
    fn handle(&self, request: Request<Incoming>) -> impl Future<Output = Response<BoxBody>> + Send {
        self.handler.handle(Arc::clone(&self.conn), request)
    }
}

/// Serve `handler` on a fresh loopback port, every connection accepted on
/// listener `http`. Each connection is told it negotiated `tls`, though it
/// is cleartext on the wire: the handler learns everything about a
/// connection from its [`ConnInfo`].
pub(crate) async fn serve<H: RequestHandler>(handler: Arc<H>, tls: Option<TlsInfo>) -> SocketAddr {
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = socket.local_addr().unwrap();
    let listener = Arc::new(ArcSwap::from_pointee(Listener {
        id: ListenerId("http".into()),
        address: local.ip(),
        port: local.port(),
        protocol: ListenProtocol::Http,
    }));
    tokio::spawn(async move {
        // Held for as long as the port is served: dropping it would drain.
        let (_drain, draining) = watch::channel(false);
        loop {
            let Ok((stream, peer)) = socket.accept().await else {
                return;
            };
            let conn = ConnInfo::new(peer, local, Arc::clone(&listener), tls.clone());
            let edge = Arc::new(Edge {
                handler: Arc::clone(&handler),
                conn: Arc::new(conn),
            });
            tokio::spawn(server::serve(stream, edge, SERVING, draining.clone()));
        }
    });
    local
}

/// What a connection that negotiated TLS for `sni` is told.
pub(crate) fn tls_info(sni: &str) -> TlsInfo {
    TlsInfo {
        sni: Some(sni.to_string()),
        version: "TLSv1.3",
        cipher: "TLS13_AES_256_GCM_SHA384".to_string(),
        alpn: Some("http/1.1".to_string()),
        resumed: false,
    }
}

// ---------------------------------------------------------------------------
// Pools
// ---------------------------------------------------------------------------

/// A pool `pool` of `scheme`, with one backend per address, selected by
/// `policy`, admitting `max_in_flight` requests at once.
pub(crate) fn pool_config(
    scheme: Scheme,
    policy: LbPolicy,
    backends: &[SocketAddr],
    max_in_flight: Option<u32>,
) -> UpstreamPool {
    UpstreamPool {
        id: PoolId("pool".into()),
        scheme,
        lb_policy: policy,
        upstreams: backends
            .iter()
            .map(|address| Upstream {
                host: address.ip().to_string(),
                port: address.port(),
                weight: 1,
            })
            .collect(),
        health_check: None,
        max_in_flight: max_in_flight.and_then(NonZeroU32::new),
    }
}

/// The pool `config` is built into, reading the health of its backends
/// from `health`: a node's, for a test that marks a backend unhealthy.
pub(crate) fn pool_reading(health: &HealthMap, config: UpstreamPool) -> Arc<Pool<Scheme>> {
    let pools = PoolSet::build(&crate::reload::pool_specs(&[config]), health).unwrap();
    Arc::clone(pools.get("pool").unwrap())
}

/// The pool `config` is built into, every backend presumed healthy: it
/// reads a health map of its own, which nothing probes.
pub(crate) fn pool_of(config: UpstreamPool) -> Arc<Pool<Scheme>> {
    pool_reading(&HealthMap::new(true), config)
}

/// A round-robin pool of `scheme` with one backend per address.
pub(crate) fn pool(scheme: Scheme, backends: &[SocketAddr]) -> Arc<Pool<Scheme>> {
    pool_of(pool_config(scheme, LbPolicy::RoundRobin, backends, None))
}

// ---------------------------------------------------------------------------
// Backends
// ---------------------------------------------------------------------------

/// Serve HTTP/1.1 and cleartext HTTP/2 (prior knowledge) on a fresh
/// loopback port, answering every request with `answer`.
pub(crate) async fn backend<F, Fut>(answer: F) -> SocketAddr
where
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Response<BoxBody>> + Send + 'static,
{
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = socket.accept().await else {
                return;
            };
            tokio::spawn(serve_backend(TokioIo::new(stream), answer.clone()));
        }
    });
    address
}

/// Serve one backend connection over `io` with `answer`.
async fn serve_backend<IO, F, Fut>(io: TokioIo<IO>, answer: F)
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response<BoxBody>> + Send + 'static,
{
    let service = hyper::service::service_fn(move |request| {
        let response = answer(request);
        async move { Ok::<_, Infallible>(response.await) }
    });
    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection(io, service)
        .await;
}

/// A backend answering every request with [`describe`].
pub(crate) async fn describing_backend() -> SocketAddr {
    backend(
        |request: Request<Incoming>| async move { Response::new(body::full(describe(&request))) },
    )
    .await
}

/// A backend answering every request `200` after `delay`.
pub(crate) async fn backend_answering_after(delay: Duration) -> SocketAddr {
    backend(move |_request| async move {
        tokio::time::sleep(delay).await;
        Response::new(body::full("late"))
    })
    .await
}

/// What a backend saw of a request: its method, target and version on the
/// first line, then one line per header, `name: value`.
pub(crate) fn describe(request: &Request<Incoming>) -> String {
    let mut text = format!(
        "{} {} {:?}\n",
        request.method(),
        request.uri(),
        request.version()
    );
    for (name, value) in request.headers() {
        text.push_str(&format!("{name}: {}\n", value.to_str().unwrap_or("?")));
    }
    text
}

/// The value of the header `name` in a [`describe`]d request, if any.
pub(crate) fn header_line<'a>(description: &'a str, name: &str) -> Option<&'a str> {
    description
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
}

/// An address nothing listens on: connecting to it is refused.
pub(crate) fn closed_port() -> SocketAddr {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap()
}

/// A TLS backend for `127.0.0.1` offering `alpn`, answering every request
/// with [`describe`]. Returns its address and the certificate (PEM) to
/// trust it by.
pub(crate) async fn tls_backend(alpn: &[&[u8]]) -> (SocketAddr, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .unwrap();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = socket.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(stream).await {
                    let answer = |request: Request<Incoming>| async move {
                        Response::new(body::full(describe(&request)))
                    };
                    serve_backend(TokioIo::new(tls), answer).await;
                }
            });
        }
    });
    (address, cert.cert.pem().into_bytes())
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

/// A request for `path` on `host`, without a body.
pub(crate) fn get(host: &str, path: &str) -> Request<BoxBody> {
    Request::builder()
        .uri(path)
        .header("host", host)
        .body(body::empty())
        .unwrap()
}

/// Send `request` to `proxy` over a new HTTP/1.1 connection.
pub(crate) async fn send(proxy: SocketAddr, request: Request<BoxBody>) -> Response<Incoming> {
    let stream = TcpStream::connect(proxy).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(connection);
    sender.send_request(request).await.unwrap()
}

/// Send `request` to `proxy` over a new HTTP/2 connection (prior
/// knowledge).
pub(crate) async fn send_h2(proxy: SocketAddr, request: Request<BoxBody>) -> Response<Incoming> {
    let stream = TcpStream::connect(proxy).await.unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(connection);
    sender.send_request(request).await.unwrap()
}

/// The body of `response`, as text.
pub(crate) async fn text(response: Response<Incoming>) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// A body sent as the test hands it frames, and where to send them; it
/// ends when the sender is dropped.
pub(crate) fn channel_body() -> (mpsc::Sender<Frame<Bytes>>, BoxBody) {
    let (sender, receiver) = mpsc::channel(16);
    (sender, body::boxed(ChannelBody(receiver)))
}

/// The receiving end of [`channel_body`].
struct ChannelBody(mpsc::Receiver<Frame<Bytes>>);

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|frame| frame.map(Ok))
    }
}
