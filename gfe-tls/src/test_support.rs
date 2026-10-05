//! Certificates for unit tests: self-signed, written to scratch files.

use gfe_config::CertEntry;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A fresh, empty directory unique to this call, so tests running in
/// parallel never share a file.
pub(crate) fn scratch_dir() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "gfe-tls-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the temp dir is writable");
    dir
}

/// A self-signed certificate for `names`, as `(certificate PEM, key PEM)`.
pub(crate) fn self_signed(names: &[&str]) -> (Vec<u8>, Vec<u8>) {
    let names = names
        .iter()
        .map(|name| name.to_string())
        .collect::<Vec<_>>();
    let cert = rcgen::generate_simple_self_signed(names).expect("rcgen signs valid names");
    (
        cert.cert.pem().into_bytes(),
        cert.key_pair.serialize_pem().into_bytes(),
    )
}

/// A certificate entry serving `sni` (and the default when `default`), with
/// its files written to a fresh scratch directory. The certificate itself
/// names the SNI names without their wildcard label.
pub(crate) fn entry(sni: &[&str], default: bool) -> CertEntry {
    let names = if sni.is_empty() {
        vec!["placeholder.local"]
    } else {
        sni.iter()
            .map(|name| name.trim_start_matches("*."))
            .collect()
    };
    let (cert, key) = self_signed(&names);
    let dir = scratch_dir();
    let entry = CertEntry {
        sni: sni.iter().map(|name| name.to_string()).collect(),
        default,
        cert_file: dir.join("tls.crt"),
        key_file: dir.join("tls.key"),
    };
    std::fs::write(&entry.cert_file, cert).expect("the scratch dir is writable");
    std::fs::write(&entry.key_file, key).expect("the scratch dir is writable");
    entry
}
