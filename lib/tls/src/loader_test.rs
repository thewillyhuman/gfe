use super::*;
use crate::test_support::{entry, scratch_dir, self_signed};

#[test]
fn loads_a_self_signed_certificate() {
    let (cert, key) = self_signed(&["example.org"]);

    let loaded = load_cert_pem(&cert, &key).unwrap();

    assert!(loaded.not_after_unix > 0);
    assert!(!loaded.certified_key.cert.is_empty());
}

/// A half-finished rotation (new certificate, old key) must not be served:
/// every handshake with it would fail.
#[test]
fn rejects_a_key_that_does_not_match_the_certificate() {
    let (cert, _) = self_signed(&["example.org"]);
    let (_, other_key) = self_signed(&["example.org"]);

    let err = load_cert_pem(&cert, &other_key).err().unwrap();

    assert!(err.to_string().contains("does not match"), "{err}");
}

#[test]
fn rejects_pem_without_a_key() {
    let (cert, _) = self_signed(&["example.org"]);

    let err = load_cert_pem(&cert, b"not a key").err().unwrap();

    assert!(err.to_string().contains("no private key"), "{err}");
}

#[test]
fn rejects_pem_without_a_certificate() {
    let (_, key) = self_signed(&["example.org"]);

    let err = load_cert_pem(b"not a certificate", &key).err().unwrap();

    assert!(err.to_string().contains("no certificate"), "{err}");
}

#[test]
fn loads_a_certificate_from_files() {
    let entry = entry(&["example.org"], false);

    let loaded = load_cert_files(&entry.cert_file, &entry.key_file).unwrap();

    assert!(loaded.not_after_unix > 0);
}

#[test]
fn a_missing_file_is_named_in_the_error() {
    let missing = scratch_dir().join("missing.crt");
    let entry = entry(&["example.org"], false);

    let err = load_cert_files(&missing, &entry.key_file).err().unwrap();

    assert!(matches!(&err, TlsError::Read { path, .. } if *path == missing));
    assert!(err.to_string().contains("missing.crt"), "{err}");
}

#[test]
fn unusable_files_are_both_named_in_the_error() {
    let entry = entry(&["example.org"], false);
    let (_, other_key) = self_signed(&["example.org"]);
    std::fs::write(&entry.key_file, other_key).unwrap();

    let err = load_cert_files(&entry.cert_file, &entry.key_file)
        .err()
        .unwrap();

    let message = err.to_string();
    assert!(message.contains("tls.crt"), "{message}");
    assert!(message.contains("tls.key"), "{message}");
    assert!(message.contains("does not match"), "{message}");
}
