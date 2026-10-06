//! Detects changes to the certificate files a dynamic config refers to.
//!
//! The dynamic config names certificate and key files by path, so replacing a
//! file in place (a rotation) does not change the config itself. The caller
//! therefore remembers what those files looked like when it last loaded them
//! and polls for a difference; that poll is what picks up a certificate
//! rotated on disk.

use gfe_config::CertEntry;
use std::path::{Path, PathBuf};

/// What identifies one version of a file on disk without reading it. `None`
/// when the file cannot be inspected (typically: it does not exist).
type Stamp = Option<FileStamp>;

/// Paths are followed through symlinks, so swapping a symlink to point at
/// another file (as Kubernetes does with mounted secrets) changes the inode.
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
    ///
    /// A rewrite in place that keeps the size is seen through the file's
    /// modification and change times, so it is missed only if it lands
    /// within the file system's timestamp granularity of the snapshot.
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
#[path = "cert_files_test.rs"]
mod tests;
