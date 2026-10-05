use super::*;
use crate::test_support::scratch_dir;

/// A certificate entry whose two files live in a fresh scratch directory.
fn entry() -> CertEntry {
    let dir = scratch_dir();
    let entry = CertEntry {
        sni: vec![],
        default: true,
        cert_file: dir.join("tls.crt"),
        key_file: dir.join("tls.key"),
    };
    std::fs::write(&entry.cert_file, b"cert v1").unwrap();
    std::fs::write(&entry.key_file, b"key v1").unwrap();
    entry
}

#[test]
fn untouched_files_are_unchanged() {
    let certs = [entry()];
    let files = CertFiles::snapshot(&certs);

    assert!(!files.changed_on_disk());
}

#[test]
fn detects_a_file_replaced_by_rename() {
    let certs = [entry()];
    let files = CertFiles::snapshot(&certs);

    // Same size on purpose: the replacement is a different inode.
    let staged = certs[0].cert_file.with_extension("new");
    std::fs::write(&staged, b"cert v2").unwrap();
    std::fs::rename(&staged, &certs[0].cert_file).unwrap();

    assert!(files.changed_on_disk());
}

#[test]
fn detects_a_file_rewritten_in_place() {
    let certs = [entry()];
    let files = CertFiles::snapshot(&certs);

    // Same inode (truncated and rewritten); a new certificate has another
    // length. A same-length rewrite is seen through its timestamps, which
    // this test cannot make differ without sleeping.
    std::fs::write(&certs[0].cert_file, b"cert version 2").unwrap();

    assert!(files.changed_on_disk());
}

#[cfg(unix)]
#[test]
fn detects_a_swapped_symlink() {
    let dir = scratch_dir();
    std::fs::create_dir(dir.join("v1")).unwrap();
    std::fs::create_dir(dir.join("v2")).unwrap();
    for version in ["v1", "v2"] {
        // Same content and size in both versions: only the inode differs.
        std::fs::write(dir.join(version).join("tls.crt"), b"cert").unwrap();
        std::fs::write(dir.join(version).join("tls.key"), b"key").unwrap();
    }
    // The layout of a Kubernetes secret volume: the files are reached through
    // a `current` symlink, which is replaced atomically by a rename.
    std::os::unix::fs::symlink("v1", dir.join("current")).unwrap();
    let certs = [CertEntry {
        sni: vec![],
        default: true,
        cert_file: dir.join("current").join("tls.crt"),
        key_file: dir.join("current").join("tls.key"),
    }];
    let files = CertFiles::snapshot(&certs);

    std::os::unix::fs::symlink("v2", dir.join("current.new")).unwrap();
    std::fs::rename(dir.join("current.new"), dir.join("current")).unwrap();

    assert!(files.changed_on_disk());
}

#[test]
fn detects_a_removed_key_file() {
    let certs = [entry()];
    let files = CertFiles::snapshot(&certs);

    std::fs::remove_file(&certs[0].key_file).unwrap();

    assert!(files.changed_on_disk());
}

#[test]
fn detects_a_file_that_appears() {
    let certs = [entry()];
    std::fs::remove_file(&certs[0].key_file).unwrap();
    let files = CertFiles::snapshot(&certs);

    std::fs::write(&certs[0].key_file, b"key v2").unwrap();

    assert!(files.changed_on_disk());
}

#[test]
fn refresh_accepts_the_current_state() {
    let certs = [entry()];
    let mut files = CertFiles::snapshot(&certs);
    std::fs::remove_file(&certs[0].key_file).unwrap();

    files.refresh();

    assert!(!files.changed_on_disk());
}
