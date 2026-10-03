//! Certificate rotation: replacing the certificate files in place must reach
//! the data plane without the dynamic config changing and without a restart.

use arc_swap::ArcSwap;
use gfe_controller::Controller;
use gfe_metrics::GfeMetrics;
use gfe_proxy::ProxyShared;
use gfe_router::RouteTable;
use gfe_tls::{CertStore, ChallengeStore, SniResolver};
use gfe_types::{LimitsConfig, TimeoutsConfig, TlsConfig};
use gfe_upstream::{HealthMap, PoolSet, UpstreamClient};
use rustls::pki_types::CertificateDer;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

fn empty_shared() -> Arc<ProxyShared> {
    Arc::new(ProxyShared {
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
    })
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
    let dir = std::env::temp_dir().join(format!("gfe-cert-reload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let original = rotate_certificate(&dir);
    let dynamic = dir.join("gfe-dynamic.json");
    std::fs::write(
        &dynamic,
        format!(
            r#"{{"certificates":[{{"default":true,"cert_file":"{0}/tls.crt","key_file":"{0}/tls.key"}}]}}"#,
            dir.display()
        ),
    )
    .unwrap();
    let bootstrap = dir.join("gfe.toml");
    std::fs::write(
        &bootstrap,
        format!(
            "[node]\nid = \"t\"\nloopback_vip = \"127.0.0.1\"\n\n\
             [control_plane]\nconfig_file = \"{}\"\n\n[health_check_defaults]\n",
            dynamic.display()
        ),
    )
    .unwrap();
    let node = gfe_config::load_node_config(&bootstrap).unwrap();

    let shared = empty_shared();
    let mut controller =
        Controller::new(shared.clone(), &node).cert_poll_interval(Duration::from_millis(50));
    controller.start().unwrap();
    assert_eq!(served_certificate(&shared), original);

    let rotated = rotate_certificate(&dir);

    let mut served = served_certificate(&shared);
    for _ in 0..100 {
        if served == rotated {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        served = served_certificate(&shared);
    }
    assert!(served == rotated, "rotated certificate was never served");
    controller.shutdown();
}
