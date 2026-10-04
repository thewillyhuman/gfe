//! Hot reload through the controller: changes on disk must reach the data
//! plane without a restart.

use gfe_controller::Controller;
use gfe_core::config::{LimitsConfig, MinVersion, TimeoutsConfig, TlsConfig};
use gfe_core::server::ServerShared;
use gfe_core::upstream::UpstreamClient;
use gfe_core::GfeError;
use gfe_observability::GfeMetrics;
use gfe_proxy::{ListenerSet, ProxyShared};
use rustls::pki_types::CertificateDer;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::watch;

/// A node under test: its scratch directory and running controller.
struct Node {
    dir: PathBuf,
    shared: Arc<ProxyShared>,
    controller: Controller,
    _shutdown: watch::Sender<bool>,
}

impl Node {
    /// Start a controller on a fresh scratch directory. `prepare` builds the
    /// initial dynamic config (JSON) given that directory.
    fn start(test: &str, prepare: impl FnOnce(&Path) -> String) -> Node {
        let dir = Node::scratch(test);
        std::fs::write(dir.join("gfe-dynamic.json"), prepare(&dir)).unwrap();
        Node::boot(dir).unwrap()
    }

    /// A fresh scratch directory for one test.
    fn scratch(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gfe-reload-{}-{test}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Start a controller on whatever `dir` holds: `gfe-dynamic.json` is the
    /// deployed dynamic config and `config-cache.json` the last-known-good
    /// cache. Either may be absent.
    fn boot(dir: PathBuf) -> Result<Node, GfeError> {
        Node::boot_adopting(dir, Vec::new())
    }

    /// [`Node::boot`] for a node that has taken over `sockets` from the node
    /// it replaces, as an in-place upgrade does.
    fn boot_adopting(
        dir: PathBuf,
        sockets: Vec<(SocketAddr, std::net::TcpListener)>,
    ) -> Result<Node, GfeError> {
        let bootstrap = dir.join("gfe.toml");
        std::fs::write(
            &bootstrap,
            format!(
                "[node]\nid = \"t\"\nloopback_vip = \"127.0.0.1\"\n\n\
                 [control_plane]\nconfig_file = \"{0}/gfe-dynamic.json\"\n\
                 local_cache = \"{0}/config-cache.json\"\nreload_debounce = \"50ms\"\n\n\
                 [health_check_defaults]\n",
                dir.display()
            ),
        )
        .unwrap();
        let node = gfe_core::config::load_node_config(&bootstrap).unwrap();

        let shared = Arc::new(ProxyShared::new(
            Arc::new(ServerShared::new(
                Arc::new(GfeMetrics::new()),
                LimitsConfig::default(),
                TimeoutsConfig::default(),
            )),
            UpstreamClient::new(1).unwrap(),
            TlsConfig::default(),
        ));
        let server_config = Arc::new(
            gfe_core::tls::server_config(shared.resolver.clone(), MinVersion::Tls12).unwrap(),
        );
        let (shutdown, shutdown_rx) = watch::channel(false);
        let listeners = Arc::new(ListenerSet::new(
            shared.server.clone(),
            shared.clone(),
            server_config,
            shutdown_rx,
        ));
        listeners.adopt(sockets);

        let mut controller = Controller::new(shared.clone(), listeners, &node)
            .cert_poll_interval(Duration::from_millis(50));
        controller.start()?;
        Ok(Node {
            dir,
            shared,
            controller,
            _shutdown: shutdown,
        })
    }

    /// Whether the node reports running on its last-known-good cache.
    fn runs_from_cache(&self) -> bool {
        self.shared
            .server
            .metrics
            .encode()
            .lines()
            .any(|line| line == "gfe_config_from_cache 1")
    }

    /// Whether the node reports that its last reload attempt failed.
    fn last_reload_failed(&self) -> bool {
        self.shared
            .server
            .metrics
            .encode()
            .lines()
            .any(|line| line == "gfe_config_reload_failed 1")
    }

    /// Replace the dynamic config the way deploy tooling does: write a
    /// sibling file, then rename it into place.
    fn deploy_dynamic(&self, json: &str) {
        let staged = self.dir.join("gfe-dynamic.json.staged");
        std::fs::write(&staged, json).unwrap();
        std::fs::rename(&staged, self.dir.join("gfe-dynamic.json")).unwrap();
    }
}

/// Poll `condition` for a few seconds; whether it became true.
async fn eventually(mut condition: impl AsyncFnMut() -> bool) -> bool {
    for _ in 0..100 {
        if condition().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// Write a fresh self-signed certificate + key into `dir`, the way a
/// rotation would: certificate first, key second. Returns the certificate.
fn rotate_certificate(dir: &Path) -> CertificateDer<'static> {
    let generated = rcgen::generate_simple_self_signed(vec!["example.org".into()]).unwrap();
    std::fs::write(dir.join("tls.crt"), generated.cert.pem()).unwrap();
    std::fs::write(dir.join("tls.key"), generated.key_pair.serialize_pem()).unwrap();
    generated.cert.der().clone()
}

fn served_certificate(shared: &ProxyShared) -> CertificateDer<'static> {
    let key = shared.resolver.current().resolve(None).unwrap();
    key.cert[0].clone()
}

#[tokio::test]
async fn serves_certificate_rotated_in_place() {
    let mut original = None;
    let node = Node::start("cert", |dir| {
        original = Some(rotate_certificate(dir));
        format!(
            r#"{{"certificates":[{{"default":true,"cert_file":"{0}/tls.crt","key_file":"{0}/tls.key"}}],"listeners":[{1}]}}"#,
            dir.display(),
            listener_json("http", free_addr())
        )
    });
    assert_eq!(Some(served_certificate(&node.shared)), original);

    let rotated = rotate_certificate(&node.dir);

    let served = eventually(async || served_certificate(&node.shared) == rotated).await;
    assert!(served, "rotated certificate was never served");
    node.controller.shutdown();
}

/// A loopback address that was free a moment ago.
fn free_addr() -> SocketAddr {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    probe.local_addr().unwrap()
}

fn listener_json(id: &str, addr: SocketAddr) -> String {
    format!(
        r#"{{"id":"{id}","address":"{}","port":{},"protocol":"http"}}"#,
        addr.ip(),
        addr.port()
    )
}

#[tokio::test]
async fn binds_listener_added_to_the_dynamic_config() {
    let first = listener_json("first", free_addr());
    let node = Node::start("listener", |_| format!(r#"{{"listeners":[{first}]}}"#));
    let added = free_addr();
    assert!(TcpStream::connect(added).await.is_err());

    node.deploy_dynamic(&format!(
        r#"{{"listeners":[{first},{}]}}"#,
        listener_json("added", added)
    ));

    let bound = eventually(async || TcpStream::connect(added).await.is_ok()).await;
    assert!(bound, "added listener was never bound");
    node.controller.shutdown();
}

/// A dynamic config whose only content is one plaintext listener on `addr`:
/// connecting to `addr` shows whether this config is the one being served.
fn config_listening_on(addr: SocketAddr) -> String {
    format!(r#"{{"listeners":[{}]}}"#, listener_json("only", addr))
}

#[tokio::test]
async fn starts_from_the_cache_when_the_dynamic_config_is_missing() {
    let dir = Node::scratch("cache-missing");
    let cached = free_addr();
    std::fs::write(dir.join("config-cache.json"), config_listening_on(cached)).unwrap();

    let node = Node::boot(dir).unwrap();

    assert!(TcpStream::connect(cached).await.is_ok());
    assert!(node.runs_from_cache());
    node.controller.shutdown();
}

#[tokio::test]
async fn starts_from_the_cache_when_the_dynamic_config_is_invalid() {
    let dir = Node::scratch("cache-invalid");
    let cached = free_addr();
    std::fs::write(dir.join("config-cache.json"), config_listening_on(cached)).unwrap();
    // A route on a listener that does not exist.
    let invalid =
        r#"{"routes":[{"id":"r","listener":"nope","host":"a","action":{"fixed":{"status":200}}}]}"#;
    std::fs::write(dir.join("gfe-dynamic.json"), invalid).unwrap();

    let node = Node::boot(dir).unwrap();

    assert!(TcpStream::connect(cached).await.is_ok());
    assert!(node.runs_from_cache());
    node.controller.shutdown();
}

#[tokio::test]
async fn refuses_to_start_with_neither_a_dynamic_config_nor_a_cache() {
    let dir = Node::scratch("cache-none");

    let result = Node::boot(dir);

    assert!(result.is_err());
}

#[tokio::test]
async fn leaves_the_cache_once_a_usable_dynamic_config_is_deployed() {
    let dir = Node::scratch("cache-recover");
    std::fs::write(
        dir.join("config-cache.json"),
        config_listening_on(free_addr()),
    )
    .unwrap();
    let node = Node::boot(dir).unwrap();
    assert!(node.runs_from_cache());

    let deployed = free_addr();
    node.deploy_dynamic(&config_listening_on(deployed));

    let serving = eventually(async || TcpStream::connect(deployed).await.is_ok()).await;
    assert!(serving, "the deployed config was never applied");
    assert!(!node.runs_from_cache());
    node.controller.shutdown();
}

/// An in-place upgrade whose deployed config is invalid: the new node must
/// start from its cache on the sockets it inherited, because the node it
/// replaces still listens on those addresses and they cannot be bound.
#[tokio::test]
async fn starts_from_the_cache_on_inherited_sockets_when_the_dynamic_config_is_invalid() {
    let dir = Node::scratch("cache-inherited");
    let inherited = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = inherited.local_addr().unwrap();
    // The predecessor's copy of the socket: it keeps listening until the
    // new node has started.
    let _predecessor = inherited.try_clone().unwrap();
    let listener = listener_json("only", addr);
    std::fs::write(
        dir.join("config-cache.json"),
        format!(
            r#"{{"listeners":[{listener}],"routes":[{{"id":"r","listener":"only","host":"*","action":{{"fixed":{{"status":200,"body":"cached"}}}}}}]}}"#
        ),
    )
    .unwrap();
    // The same listener, and a route forwarding to a pool that does not exist.
    std::fs::write(
        dir.join("gfe-dynamic.json"),
        format!(
            r#"{{"listeners":[{listener}],"routes":[{{"id":"r","listener":"only","host":"*","action":{{"forward":"missing"}}}}]}}"#
        ),
    )
    .unwrap();

    let node = Node::boot_adopting(dir, vec![(addr, inherited)]).unwrap();

    assert!(node.runs_from_cache());
    assert!(http_get(addr).await.ends_with("cached"));
    node.controller.shutdown();
}

/// The full response to a plain `GET /` sent to `addr`.
async fn http_get(addr: SocketAddr) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nhost: a.example.org\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_string(&mut response))
        .await
        .expect("the node did not answer")
        .unwrap();
    response
}

#[tokio::test]
async fn reports_a_rejected_reload_until_a_good_one() {
    let first = free_addr();
    let node = Node::start("reload-failed", |_| config_listening_on(first));
    let clean_start = node.shared.server.metrics.encode();
    assert!(
        clean_start.contains("gfe_config_reload_failed 0"),
        "{clean_start}"
    );

    node.deploy_dynamic(r#"{"listeners":[]}"#);
    let rejected = eventually(async || node.last_reload_failed()).await;
    assert!(rejected, "the rejected reload was never reported");

    let second = free_addr();
    node.deploy_dynamic(&config_listening_on(second));
    let recovered = eventually(async || !node.last_reload_failed()).await;
    assert!(recovered, "the good reload never cleared the failure");
    node.controller.shutdown();
}

#[tokio::test]
async fn reports_a_failed_reload_when_starting_from_the_cache() {
    let dir = Node::scratch("reload-failed-cache");
    std::fs::write(
        dir.join("config-cache.json"),
        config_listening_on(free_addr()),
    )
    .unwrap();

    let node = Node::boot(dir).unwrap();

    assert!(node.last_reload_failed());
    node.controller.shutdown();
}
