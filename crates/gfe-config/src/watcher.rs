//! inotify-based config file watcher with debounce.
//!
//! The watcher observes the config file's *parent directory* (robust against
//! editors/deploy tooling that replace the file via rename) and invokes a
//! caller-supplied reload closure after a debounce window. The reload closure
//! runs inside the Tokio runtime, so it may spawn tasks (e.g. health probes).
//!
//! Only events that can change what the file contains count. On Linux the
//! watcher is also told when the file is merely opened or read, which is
//! exactly what a reload does: reacting to those would make every reload
//! trigger the next one.

use gfe_types::GfeError;
use notify::event::{AccessKind, AccessMode, EventKind, ModifyKind};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// Whether an event of this kind can mean the file has new content: it was
/// created, written, renamed into place or removed. Opening, reading and
/// metadata-only changes (permissions, timestamps) cannot.
fn may_change_content(kind: &EventKind) -> bool {
    match kind {
        EventKind::Access(AccessKind::Close(AccessMode::Write)) => true,
        EventKind::Access(_) => false,
        EventKind::Modify(ModifyKind::Metadata(_)) => false,
        // Create, remove, data and name changes, and whatever a platform
        // cannot classify: reloading once too often is harmless.
        _ => true,
    }
}

/// Watch `path` and call `reload` (debounced) whenever it changes. The
/// returned `RecommendedWatcher` must be kept alive for watching to continue.
pub fn spawn_watcher(
    path: &Path,
    debounce: Duration,
    reload: Arc<dyn Fn() + Send + Sync>,
) -> Result<RecommendedWatcher, GfeError> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(16);

    // We watch the parent directory (robust against rename-replace), so we must
    // filter events down to the config file itself — otherwise writing the
    // last-known-good cache into the same directory would retrigger reloads in
    // an infinite loop.
    let target_name = path.file_name().map(|s| s.to_os_string());

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            let touches_config = event
                .paths
                .iter()
                .any(|p| p.file_name() == target_name.as_deref());
            if touches_config && may_change_content(&event.kind) {
                // Best-effort: drop the signal if the channel is full (a reload
                // is already pending, which picks up the latest file contents).
                let _ = tx.try_send(());
            }
        }
    })
    .map_err(|e| GfeError::Config(format!("creating watcher: {e}")))?;

    let watch_dir = path.parent().unwrap_or(Path::new("."));
    watcher
        .watch(watch_dir, RecursiveMode::NonRecursive)
        .map_err(|e| GfeError::Config(format!("watching {}: {e}", watch_dir.display())))?;

    tokio::spawn(async move {
        loop {
            // Wait for the first change event.
            if rx.recv().await.is_none() {
                break;
            }
            // Debounce: keep draining until quiet for `debounce`.
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(debounce) => break,
                    ev = rx.recv() => {
                        if ev.is_none() {
                            return;
                        }
                    }
                }
            }
            reload();
        }
    });

    Ok(watcher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{AccessKind, AccessMode, CreateKind, DataChange, MetadataKind, RenameMode};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn writing_or_replacing_the_file_is_a_change() {
        for kind in [
            EventKind::Create(CreateKind::File),
            EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            EventKind::Modify(ModifyKind::Name(RenameMode::To)),
            EventKind::Access(AccessKind::Close(AccessMode::Write)),
        ] {
            assert!(may_change_content(&kind), "{kind:?}");
        }
    }

    #[test]
    fn opening_or_reading_the_file_is_not_a_change() {
        for kind in [
            EventKind::Access(AccessKind::Open(AccessMode::Any)),
            EventKind::Access(AccessKind::Read),
            EventKind::Access(AccessKind::Close(AccessMode::Read)),
        ] {
            assert!(!may_change_content(&kind), "{kind:?}");
        }
    }

    #[test]
    fn a_metadata_change_alone_is_not_a_change() {
        let kind = EventKind::Modify(ModifyKind::Metadata(MetadataKind::AccessTime));
        assert!(!may_change_content(&kind));
    }

    /// The reload reads the file it watches. On Linux that read is itself
    /// reported by the watcher, and must not start another reload.
    #[tokio::test]
    async fn reload_that_reads_the_file_does_not_trigger_itself() {
        let dir = std::env::temp_dir().join(format!("gfe-watch-loop-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("dynamic.json");
        std::fs::write(&file, b"{}").unwrap();

        let count = Arc::new(AtomicUsize::new(0));
        let reload: Arc<dyn Fn() + Send + Sync> = Arc::new({
            let (count, file) = (count.clone(), file.clone());
            move || {
                std::fs::read(&file).unwrap();
                count.fetch_add(1, Ordering::SeqCst);
            }
        });
        let _watcher = spawn_watcher(&file, Duration::from_millis(20), reload).unwrap();

        std::fs::write(&file, br#"{"x":1}"#).unwrap();
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // One change, one reload; a platform may report the write as two
        // events far enough apart for a second one. A loop would be dozens.
        let reloads = count.load(Ordering::SeqCst);
        assert!((1..=2).contains(&reloads), "reloaded {reloads} times");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn reload_fires_on_change() {
        let dir = std::env::temp_dir().join(format!("gfe-watch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("dynamic.json");
        std::fs::write(&file, b"{}").unwrap();

        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        let reload: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
        });

        let _watcher = spawn_watcher(&file, Duration::from_millis(50), reload).unwrap();

        // Modify the file a few times.
        for i in 0..3 {
            std::fs::write(&file, format!("{{\"x\":{i}}}").as_bytes()).unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert!(
            count.load(Ordering::SeqCst) >= 1,
            "reload should have fired at least once"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
