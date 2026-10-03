//! Hot reload through the controller: changes on disk must reach the data
//! plane without a restart.

use arc_swap::ArcSwap;
use gfe_controller::Controller;
use gfe_metrics::GfeMetrics;
use gfe_proxy::{ListenerSet, ProxyShared};
use gfe_router::RouteTable;
use gfe_tls::{CertStore, ChallengeStore, SniResolver};
use gfe_types::{LimitsConfig, MinVersion, TimeoutsConfig, TlsConfig};
use gfe_upstream::{HealthMap, PoolSet, UpstreamClient};
use rustls::pki_types::CertificateDer;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
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
    /// Start a controller on a fresh scratch directory. `dynamic` builds the
    /// initial dynamic config (JSON) given that directory.
    fn start(test: &str, prepare: impl FnOnce(&Path) -> String) -> Node {
        let dir = std::env::temp_dir().join(format!("gfe-reload-{}-{test}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("gfe-dynamic.json"), prepare(&dir)).unwrap();
        let bootstrap = dir.join("gfe.toml");
        std::fs::write(
            &bootstrap,
            format!(
                "[node]\nid = \"t\"\nloopback_vip = \"127.0.0.1\"\n\n\
                 [control_plane]\nconfig_file = \"{}\"\nreload_debounce = \"50ms\"\n\n\
                 [health_check_defaults]\n",
                dir.join("gfe-dynamic.json").display()
            ),
        )
        .unwrap();
        let node = gfe_config::load_node_config(&bootstrap).unwrap();

        let shared = Arc::new(ProxyShared {
            routes: ArcSwap::from_pointee(RouteTable::default()),
            pools: ArcSwap::from_pointee(PoolSet::default()),
            resolver: Arc::new(SniResolver::new(CertStore::default())),
            challenges: Arc::new(ChallengeStore::new()),
            health: Arc::new(HealthMap::new(true)),
            upstream: UpstreamClient::new(1).unwrap(),
            metrics: Arc::new(GfeMetrics::new()),
            limits: LimitsConfig::default(),
            timeouts: TimeoutsConfig::default(),
            tls: TlsConfig::default(),
            draining: AtomicBool::new(false),
        });
        let server_config =
            Arc::new(gfe_tls::server_config(shared.resolver.clone(), MinVersion::Tls12).unwrap());
        let (shutdown, shutdown_rx) = watch::channel(false);
        let listeners = Arc::new(ListenerSet::new(shared.clone(), server_config, shutdown_rx));

        let mut controller = Controller::new(shared.clone(), listeners, &node)
            .cert_poll_interval(Duration::from_millis(50));
        controller.start().unwrap();
        Node {
            dir,
            shared,
            controller,
            _shutdown: shutdown,
        }
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
            r#"{{"certificates":[{{"default":true,"cert_file":"{0}/tls.crt","key_file":"{0}/tls.key"}}]}}"#,
            dir.display()
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
