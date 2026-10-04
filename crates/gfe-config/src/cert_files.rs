//! Detects changes to the certificate files a dynamic config refers to.
//!
//! The dynamic config names certificate and key files by path, so replacing a
//! file in place (a rotation) does not change the config itself. The
//! controller therefore remembers what those files looked like when it last
//! loaded them and polls for a difference.

use gfe_core::config::CertEntry;
use std::path::{Path, PathBuf};

/// What identifies one version of a file on disk without reading it. `None`
/// when the file cannot be inspected (typically: it does not exist).
type Stamp = Option<FileStamp>;

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStamp {
    inode: u64,
    size: u64,
    modified_ns: (i64, i64),
    changed_ns: (i64, i64),
}

#[cfg(not(unix))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStamp {
    size: u64,
    modified: Option<std::time::SystemTime>,
}

#[cfg(unix)]
fn stamp(path: &Path) -> Stamp {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).ok()?;
    Some(FileStamp {
        inode: meta.ino(),
        size: meta.size(),
        modified_ns: (meta.mtime(), meta.mtime_nsec()),
        changed_ns: (meta.ctime(), meta.ctime_nsec()),
    })
}

#[cfg(not(unix))]
fn stamp(path: &Path) -> Stamp {
    let meta = std::fs::metadata(path).ok()?;
    Some(FileStamp {
        size: meta.len(),
        modified: meta.modified().ok(),
    })
}

/// The certificate and key files of a dynamic config, as seen on disk at one
/// point in time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertFiles {
    seen: Vec<(PathBuf, Stamp)>,
}

impl CertFiles {
    /// Record how the files referenced by `certificates` look right now.
    ///
    /// Take the snapshot *before* reading the files: a file replaced in
    /// between then shows up as changed, instead of going unnoticed.
    pub fn snapshot(certificates: &[CertEntry]) -> Self {
        let seen = certificates
            .iter()
            .flat_map(|entry| [&entry.cert_file, &entry.key_file])
            .map(|path| (path.clone(), stamp(path)))
            .collect();
        CertFiles { seen }
    }

    /// Whether any of the files differs from the snapshot: replaced,
    /// rewritten, removed, created, or with changed ownership or permissions.
    pub fn changed_on_disk(&self) -> bool {
        self.seen.iter().any(|(path, seen)| stamp(path) != *seen)
    }

    /// Re-take the snapshot of the same files.
    pub fn refresh(&mut self) {
        for (path, seen) in &mut self.seen {
            *seen = stamp(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A certificate entry whose two files live in a fresh scratch directory.
    fn entry(test: &str) -> CertEntry {
        let dir = std::env::temp_dir().join(format!("gfe-certfiles-{}-{test}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
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
        let certs = [entry("untouched")];
        let files = CertFiles::snapshot(&certs);

        assert!(!files.changed_on_disk());
    }

    #[test]
    fn detects_file_replaced_by_rename() {
        let certs = [entry("rename")];
        let files = CertFiles::snapshot(&certs);

        // Same size on purpose: the replacement is a different inode.
        let staged = certs[0].cert_file.with_extension("new");
        std::fs::write(&staged, b"cert v2").unwrap();
        std::fs::rename(&staged, &certs[0].cert_file).unwrap();

        assert!(files.changed_on_disk());
    }

    #[test]
    fn detects_removed_key_file() {
        let certs = [entry("removed")];
        let files = CertFiles::snapshot(&certs);

        std::fs::remove_file(&certs[0].key_file).unwrap();

        assert!(files.changed_on_disk());
    }

    #[test]
    fn refresh_accepts_the_current_state() {
        let certs = [entry("refresh")];
        let mut files = CertFiles::snapshot(&certs);
        std::fs::remove_file(&certs[0].key_file).unwrap();

        files.refresh();

        assert!(!files.changed_on_disk());
    }
}
