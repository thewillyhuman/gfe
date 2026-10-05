use super::*;
use pingora_core::upstreams::peer::Peer;

fn waits() -> Waits {
    Waits {
        connect: Duration::from_secs(3),
        first_byte: Duration::from_secs(30),
        idle: Duration::from_secs(60),
    }
}

fn peer(scheme: Scheme, grpc: bool) -> HttpPeer {
    build(
        "10.0.0.1:8443".parse().unwrap(),
        "backend.example.org",
        scheme,
        grpc,
        Duration::from_secs(20),
        &waits(),
        &UpstreamTls::default(),
    )
}

#[test]
fn http_pool_is_cleartext_http1() {
    let peer = peer(Scheme::Http, false);

    assert!(!peer.is_tls());
    assert_eq!(peer.options.alpn, ALPN::H1);
}

#[test]
fn https_pool_is_tls_http1_verified_against_the_backends_name() {
    let peer = peer(Scheme::Https, false);

    assert!(peer.is_tls());
    assert_eq!(peer.options.alpn, ALPN::H1);
    assert_eq!(peer.sni, "backend.example.org");
    assert!(peer.options.verify_cert && peer.options.verify_hostname);
    assert_eq!(peer.options.total_connection_timeout, Some(waits().connect));
}

#[test]
fn grpc_call_to_an_https_pool_offers_http2_by_alpn_on_connections_of_its_own() {
    let grpc = peer(Scheme::Https, true);
    let plain = peer(Scheme::Https, false);

    assert_eq!(grpc.options.alpn, ALPN::H2H1);
    assert_ne!(grpc.reuse_hash(), plain.reuse_hash());
}

#[test]
fn h2c_pool_is_cleartext_http2_with_prior_knowledge() {
    let peer = peer(Scheme::H2c, false);

    assert!(!peer.is_tls());
    assert_eq!(peer.options.alpn, ALPN::H2);
    assert_eq!(peer.options.max_h2_streams, MAX_H2_STREAMS);
    assert_eq!(peer.options.h2_ping_interval, Some(waits().first_byte));
}

#[test]
fn request_waits_for_its_backend_as_long_as_it_may() {
    let peer = peer(Scheme::Http, false);

    assert_eq!(peer.options.connection_timeout, Some(waits().connect));
    assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(20)));
    assert_eq!(peer.options.write_timeout, Some(waits().first_byte));
    assert_eq!(peer.options.idle_timeout, Some(waits().idle));
}

#[test]
fn grpc_call_is_not_bounded_by_read_or_write_timeouts() {
    let peer = peer(Scheme::H2c, true);

    assert_eq!(peer.options.read_timeout, None);
    assert_eq!(peer.options.write_timeout, None);
}

/// A self-signed certificate and its key, written to temporary files.
fn certificate_files(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let cert = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
    let dir = std::env::temp_dir();
    let tag = format!("gfe-core-peer-{}-{name}", std::process::id());
    let cert_file = dir.join(format!("{tag}.crt"));
    let key_file = dir.join(format!("{tag}.key"));
    std::fs::write(&cert_file, cert.cert.pem()).unwrap();
    std::fs::write(&key_file, cert.key_pair.serialize_pem()).unwrap();
    (cert_file, key_file)
}

#[test]
fn trusts_the_extra_ca_on_top_of_the_system_roots() {
    let (ca, _) = certificate_files("extra-ca");
    let config = UpstreamConfig {
        extra_ca_file: Some(ca),
        ..Default::default()
    };

    let tls = UpstreamTls::load(&config).unwrap();
    let peer = build(
        "10.0.0.1:443".parse().unwrap(),
        "backend",
        Scheme::Https,
        false,
        Duration::from_secs(1),
        &waits(),
        &tls,
    );

    let roots = peer.options.ca.expect("a CA list");
    assert!(!roots.is_empty());
}

#[test]
fn presents_the_configured_client_certificate() {
    let (cert, key) = certificate_files("client");
    let config = UpstreamConfig {
        client_cert_file: Some(cert),
        client_key_file: Some(key),
        ..Default::default()
    };

    let tls = UpstreamTls::load(&config).unwrap();
    let peer = build(
        "10.0.0.1:443".parse().unwrap(),
        "backend",
        Scheme::Https,
        false,
        Duration::from_secs(1),
        &waits(),
        &tls,
    );

    assert!(peer.client_cert_key.is_some());
}

#[test]
fn cleartext_peers_carry_no_tls_material() {
    let (cert, key) = certificate_files("client-cleartext");
    let config = UpstreamConfig {
        client_cert_file: Some(cert),
        client_key_file: Some(key),
        ..Default::default()
    };
    let tls = UpstreamTls::load(&config).unwrap();

    let peer = build(
        "10.0.0.1:80".parse().unwrap(),
        "backend",
        Scheme::Http,
        false,
        Duration::from_secs(1),
        &waits(),
        &tls,
    );

    assert!(peer.client_cert_key.is_none());
    assert!(peer.options.ca.is_none());
}

#[test]
fn refuses_a_client_certificate_without_its_key() {
    let (cert, _) = certificate_files("client-alone");
    let config = UpstreamConfig {
        client_cert_file: Some(cert),
        ..Default::default()
    };

    let error = UpstreamTls::load(&config).unwrap_err();

    assert!(matches!(error, ProxyError::IncompleteClientCertificate));
}

#[test]
fn refuses_an_extra_ca_file_without_certificates() {
    let empty =
        std::env::temp_dir().join(format!("gfe-core-peer-{}-empty.pem", std::process::id()));
    std::fs::write(&empty, "").unwrap();
    let config = UpstreamConfig {
        extra_ca_file: Some(empty),
        ..Default::default()
    };

    let error = UpstreamTls::load(&config).unwrap_err().to_string();

    assert!(error.contains("extra_ca_file"), "{error}");
    assert!(error.contains("no certificate"), "{error}");
}
