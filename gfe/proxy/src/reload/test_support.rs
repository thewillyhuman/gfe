//! What the unit tests of `reload` share: scratch directories, listeners
//! and certificates.

use gfe_config::{CertEntry, ListenProtocol, Listener, ListenerId};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

/// An empty directory of its own for `test`.
pub(crate) fn scratch_dir(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gfe-core-reload-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A plaintext listener `id` on loopback port `port`.
pub(crate) fn http_listener(id: &str, port: u16) -> Listener {
    Listener {
        id: ListenerId(id.into()),
        address: "127.0.0.1".parse().unwrap(),
        port,
        protocol: ListenProtocol::Http,
    }
}

/// A certificate entry for `names`, its self-signed certificate and key in
/// files of their own.
pub(crate) fn cert_entry(names: &[&str]) -> CertEntry {
    static FILES: AtomicUsize = AtomicUsize::new(0);
    let n = FILES.fetch_add(1, Ordering::Relaxed);
    let names: Vec<String> = names.iter().map(|name| name.to_string()).collect();
    let generated = rcgen::generate_simple_self_signed(names.clone()).unwrap();
    let dir = std::env::temp_dir();
    let tag = format!("gfe-core-reload-{}-{n}", std::process::id());
    let cert_file = dir.join(format!("{tag}.crt"));
    let key_file = dir.join(format!("{tag}.key"));
    std::fs::write(&cert_file, generated.cert.pem()).unwrap();
    std::fs::write(&key_file, generated.key_pair.serialize_pem()).unwrap();
    CertEntry {
        sni: names,
        default: false,
        cert_file,
        key_file,
    }
}
