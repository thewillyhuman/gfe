//! The cost of TLS termination per connection: a full TLS 1.3 handshake
//! (ECDSA P-256, in memory, no I/O), and the per-ClientHello SNI certificate
//! lookup on its own.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use netkit_tls::{CertSpec, CertStore, MinVersion, SniResolver, server_config};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn temp_cert() -> (PathBuf, PathBuf) {
    let cert = rcgen::generate_simple_self_signed(vec!["bench.local".to_string()]).unwrap();
    let dir = std::env::temp_dir();
    let cp = dir.join(format!("netkit-tls-bench-{}.crt", std::process::id()));
    let kp = dir.join(format!("netkit-tls-bench-{}.key", std::process::id()));
    std::fs::write(&cp, cert.cert.pem()).unwrap();
    std::fs::write(&kp, cert.key_pair.serialize_pem()).unwrap();
    (cp, kp)
}

fn client_config(cert_path: &Path) -> Arc<rustls::ClientConfig> {
    let pem = std::fs::read(cert_path).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut &pem[..]) {
        roots.add(c.unwrap()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(cfg)
}

/// Drive one full in-memory TLS handshake (client + server) to completion.
fn one_handshake(server_cfg: Arc<rustls::ServerConfig>, client_cfg: Arc<rustls::ClientConfig>) {
    let name = rustls::pki_types::ServerName::try_from("bench.local").unwrap();
    let mut client = rustls::ClientConnection::new(client_cfg, name).unwrap();
    let mut server = rustls::ServerConnection::new(server_cfg).unwrap();
    let mut buf = Vec::new();

    while client.is_handshaking() || server.is_handshaking() {
        buf.clear();
        while client.wants_write() {
            client.write_tls(&mut buf).unwrap();
        }
        let mut r = &buf[..];
        while !r.is_empty() {
            server.read_tls(&mut r).unwrap();
        }
        server.process_new_packets().unwrap();

        buf.clear();
        while server.wants_write() {
            server.write_tls(&mut buf).unwrap();
        }
        let mut r = &buf[..];
        while !r.is_empty() {
            client.read_tls(&mut r).unwrap();
        }
        client.process_new_packets().unwrap();
    }
}

fn bench(c: &mut Criterion) {
    let (cp, kp) = temp_cert();
    let store = CertStore::build(&[CertSpec {
        sni: vec!["bench.local".into()],
        default: true,
        cert_file: cp.clone(),
        key_file: kp,
    }])
    .unwrap();
    let resolver = Arc::new(SniResolver::new(store));
    let server_cfg = Arc::new(server_config(resolver.clone(), MinVersion::Tls13).unwrap());
    let client_cfg = client_config(&cp);

    c.bench_function("tls13_full_handshake_ecdsa_p256", |b| {
        b.iter(|| one_handshake(black_box(server_cfg.clone()), black_box(client_cfg.clone())))
    });

    // SNI certificate resolution (per-ClientHello lookup) in isolation.
    let store = resolver.current();
    c.bench_function("sni_cert_resolve", |b| {
        b.iter(|| black_box(store.resolve(black_box(Some("bench.local")))))
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
