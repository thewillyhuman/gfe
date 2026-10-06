use super::*;
use crate::edge::test_support::{TestCert, acceptor, connector};
use rustls::pki_types::ServerName;

fn shared(metrics: Arc<GfeMetrics>) -> Shared {
    Shared::new(metrics, LimitsConfig::default(), TimeoutsConfig::default())
}

#[test]
fn publishes_connection_limits_as_gauges() {
    let metrics = Arc::new(GfeMetrics::new());
    let limits = LimitsConfig {
        max_connections: 7,
        max_connections_listener: 3,
        ..Default::default()
    };

    Shared::new(metrics.clone(), limits, TimeoutsConfig::default());

    let exposed = metrics.encode();
    assert!(exposed.contains("gfe_connections_limit 7"), "{exposed}");
    assert!(
        exposed.contains("gfe_listener_connections_limit 3"),
        "{exposed}"
    );
}

struct FixedAcceptQueue;

impl AcceptQueue for FixedAcceptQueue {
    fn waited(&self, _local: SocketAddr, _peer: SocketAddr) -> Option<Duration> {
        Some(Duration::from_millis(5))
    }
}

#[test]
fn knows_how_long_a_connection_waited_only_with_a_kernel_view() {
    let metrics = Arc::new(GfeMetrics::new());
    let without = shared(metrics.clone());
    let with = shared(metrics).with_accept_queue(Arc::new(FixedAcceptQueue));
    let addr: SocketAddr = "127.0.0.1:443".parse().unwrap();

    assert_eq!(without.accept_wait(addr, addr), None);
    assert_eq!(with.accept_wait(addr, addr), Some(Duration::from_millis(5)));
}

/// Run a handshake asking for `sni` against `acceptor`, which fails.
async fn failed_handshake(acceptor: &netkit_tls::Acceptor, trusted: &TestCert, sni: &str) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let client = connector(&[trusted], &[b"http/1.1"]);
    let name = ServerName::try_from(sni.to_string()).unwrap();
    let (client, server) =
        tokio::join!(client.connect(name, client_io), acceptor.accept(server_io));
    assert!(client.is_err() && server.is_err());
}

#[tokio::test]
async fn counts_the_handshakes_that_found_no_certificate_once_each() {
    let (acceptor, resolver) = acceptor(&[]);
    let trusted = TestCert::new("a.example.org");
    let metrics = Arc::new(GfeMetrics::new());
    let shared = shared(metrics.clone()).with_sni_resolver(resolver);

    failed_handshake(&acceptor, &trusted, "a.example.org").await;
    shared.export_sni_misses();
    failed_handshake(&acceptor, &trusted, "b.example.org").await;
    shared.export_sni_misses();
    shared.export_sni_misses();

    let exposed = metrics.encode();
    assert!(exposed.contains("gfe_tls_sni_no_cert_total 2"), "{exposed}");
}

#[test]
fn exports_nothing_without_a_resolver() {
    let metrics = Arc::new(GfeMetrics::new());

    shared(metrics.clone()).export_sni_misses();

    let exposed = metrics.encode();
    assert!(exposed.contains("gfe_tls_sni_no_cert_total 0"), "{exposed}");
}
