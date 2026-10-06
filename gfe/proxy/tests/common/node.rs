//! A whole front end, as a node runs it: started from a bootstrap config and
//! a dynamic config file in a scratch directory of its own, terminating TLS
//! at the edge and following its config. Plus TLS clients to talk to it.

use super::{Answer, collect};
use gfe_config::{
    ControlPlaneConfig, DynamicConfig, ListenProtocol, Listener, ListenerId, NodeConfig,
    NodeSection,
};
use gfe_proxy::metrics::GfeMetrics;
use gfe_proxy::{Frontend, StartError};
use http_body_util::Empty;
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use netkit_http::Bytes;
use rustls::pki_types::{CertificateDer, ServerName};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// How often a test node checks its certificate files for a rotation.
pub const CERT_POLL: Duration = Duration::from_millis(50);

/// A front end serving the config of its scratch directory:
/// `gfe-dynamic.json` is the deployed dynamic config and
/// `config-cache.json` the last-known-good cache.
pub struct Node {
    pub dir: PathBuf,
    pub frontend: Frontend,
    pub metrics: Arc<GfeMetrics>,
}

/// An empty directory of its own for `test`.
pub fn scratch(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gfe-core-node-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The bootstrap config of a node whose files are in `dir`: every default,
/// one worker thread, a short reload debounce.
pub fn bootstrap(dir: &Path) -> NodeConfig {
    NodeConfig {
        node: NodeSection {
            id: "test".into(),
            loopback_vip: None,
            metrics_addr: "127.0.0.1:0".parse().unwrap(),
            worker_threads: 1,
        },
        control_plane: ControlPlaneConfig {
            config_file: dir.join("gfe-dynamic.json"),
            local_cache: Some(dir.join("config-cache.json")),
            reload_debounce: Duration::from_millis(50),
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

/// Write `config` to `path` as JSON.
pub fn write_config(path: &Path, config: &DynamicConfig) {
    std::fs::write(path, serde_json::to_vec_pretty(config).unwrap()).unwrap();
}

impl Node {
    /// A node of `test` serving `config`, with every default.
    pub fn serving(test: &str, config: &DynamicConfig) -> Node {
        Node::serving_with(test, config, |_| {})
    }

    /// A node of `test` serving `config`, its bootstrap config changed by
    /// `tweak`.
    pub fn serving_with(
        test: &str,
        config: &DynamicConfig,
        tweak: impl FnOnce(&mut NodeConfig),
    ) -> Node {
        let dir = scratch(test);
        write_config(&dir.join("gfe-dynamic.json"), config);
        let mut node = bootstrap(&dir);
        tweak(&mut node);
        Node::boot(dir, &node, Vec::new()).expect("the node starts")
    }

    /// Start a node on whatever `dir` holds, with the sockets `inherited`
    /// from a node it replaces.
    pub fn boot(
        dir: PathBuf,
        node: &NodeConfig,
        inherited: Vec<(SocketAddr, std::net::TcpListener)>,
    ) -> Result<Node, StartError> {
        let metrics = Arc::new(GfeMetrics::new());
        let frontend = Frontend::start_polling_certificates_every(
            node,
            Arc::clone(&metrics),
            inherited,
            CERT_POLL,
        )?;
        Ok(Node {
            dir,
            frontend,
            metrics,
        })
    }

    /// Replace the dynamic config the way deploy tooling does: write a
    /// sibling file, then rename it into place.
    pub fn deploy(&self, config: &DynamicConfig) {
        let staged = self.dir.join("gfe-dynamic.json.staged");
        write_config(&staged, config);
        std::fs::rename(&staged, self.dir.join("gfe-dynamic.json")).unwrap();
    }

    /// The address listener `id` is bound to.
    pub fn addr(&self, id: &str) -> SocketAddr {
        self.frontend
            .local_addr(&ListenerId(id.into()))
            .unwrap_or_else(|| panic!("listener {id} is not running"))
    }

    /// The metrics, as Prometheus scrapes them.
    pub fn metrics(&self) -> String {
        self.frontend.refresh_metrics();
        self.metrics.encode()
    }

    /// Whether the metrics have exactly this line.
    pub fn has_metric(&self, line: &str) -> bool {
        self.metrics().lines().any(|l| l == line)
    }

    /// Wait until the metrics contain `text`, failing the test if they do
    /// not within a few seconds.
    pub async fn wait_for_metric(&self, text: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let metrics = self.metrics();
            if metrics.contains(text) {
                return;
            }
            assert!(Instant::now() < deadline, "missing {text} in:\n{metrics}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// Poll `condition` for a few seconds; whether it became true.
pub async fn eventually(mut condition: impl AsyncFnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if condition().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// A loopback port that was free a moment ago. Listeners are identified by
/// the address they are configured on, so two listeners of one config
/// cannot both be on port 0.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A listener `id` of `protocol` on loopback port `port` (0: any).
pub fn listener(id: &str, protocol: ListenProtocol, port: u16) -> Listener {
    Listener {
        id: ListenerId(id.into()),
        address: "127.0.0.1".parse().unwrap(),
        port,
        protocol,
    }
}

// ---------------------------------------------------------------------------
// TLS clients
// ---------------------------------------------------------------------------

/// A TLS client trusting `roots`, offering `versions` and `alpn`. A client
/// keeps the sessions it was given, so a second connection of the same
/// client offers to resume.
pub fn tls_client(
    roots: &[CertificateDer<'static>],
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn: &[&[u8]],
) -> TlsConnector {
    let mut store = rustls::RootCertStore::empty();
    for root in roots {
        store.add(root.clone()).unwrap();
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(versions)
    .unwrap()
    .with_root_certificates(store)
    .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    TlsConnector::from(Arc::new(config))
}

/// A TLS client trusting `roots` with the default versions, speaking
/// HTTP/1.1.
pub fn h1_tls_client(roots: &[CertificateDer<'static>]) -> TlsConnector {
    tls_client(roots, rustls::DEFAULT_VERSIONS, &[b"http/1.1"])
}

/// A TLS connection to `addr` asking for `sni`.
pub async fn tls_connect(
    client: &TlsConnector,
    addr: SocketAddr,
    sni: &str,
) -> std::io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    client
        .connect(ServerName::try_from(sni.to_string()).unwrap(), tcp)
        .await
}

/// The certificate the server presented on `stream`.
pub fn served_certificate(stream: &TlsStream<TcpStream>) -> CertificateDer<'static> {
    stream.get_ref().1.peer_certificates().unwrap()[0].clone()
}

/// `GET path` for `host` over HTTP/1.1, on `stream`.
pub async fn get_over<S>(stream: S, host: &str, path: &str) -> Answer
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .uri(path)
        .header("host", host)
        .body(Empty::<Bytes>::new())
        .unwrap();
    collect(sender.send_request(req).await.unwrap()).await
}

/// `GET https://host/path` over HTTP/2, on `stream` (ALPN `h2`).
pub async fn h2_get_over<S>(stream: S, host: &str, path: &str) -> Answer
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .uri(format!("https://{host}{path}"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = sender.send_request(req).await.unwrap();
    assert_eq!(response.version(), netkit_http::Version::HTTP_2);
    collect(response).await
}
