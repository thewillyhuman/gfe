//! Noticing that the dynamic config file changed, with a debounce.
//!
//! The watcher observes the file's *parent directory* (robust against
//! editors and deploy tooling that replace the file by renaming another
//! over it) and calls a reload once the file has been quiet for the
//! debounce window. The reload runs inside the Tokio runtime, so it may
//! spawn tasks (health probes, accept loops).
//!
//! Only events that can change what the file contains count. On Linux the
//! watcher is also told when the file is merely opened or read, which is
//! exactly what a reload does: reacting to those would make every reload
//! trigger the next one.

use crate::reload::ReloadError;
use notify::event::{AccessKind, AccessMode, EventKind, ModifyKind};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
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

/// Watch `path` and call `reload` once it has stopped changing for
/// `debounce`. Watching lasts as long as the returned watcher: dropping it
/// stops the watching and the task that calls `reload`.
///
/// Must be called from within a Tokio runtime.
pub(crate) fn watch(
    path: &Path,
    debounce: Duration,
    reload: impl Fn() + Send + 'static,
) -> Result<RecommendedWatcher, ReloadError> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(16);

    // The parent directory is watched, so events are filtered down to the
    // config file itself: otherwise writing the last-known-good cache into
    // the same directory would trigger reloads for ever.
    let target_name = path.file_name().map(|name| name.to_os_string());
    let watch_error = |error| ReloadError::Watch {
        path: path.to_path_buf(),
        error,
    };

    let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
        if let Ok(event) = event {
            let touches_config = event
                .paths
                .iter()
                .any(|p| p.file_name() == target_name.as_deref());
            if touches_config && may_change_content(&event.kind) {
                // A full channel means a reload is already pending, and it
                // reads the file as it is then.
                let _ = tx.try_send(());
            }
        }
    })
    .map_err(watch_error)?;

    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    watcher
        .watch(dir, RecursiveMode::NonRecursive)
        .map_err(watch_error)?;

    tokio::spawn(async move {
        // `recv` returns `None` once the watcher, and its sender, are gone.
        while rx.recv().await.is_some() {
            loop {
                tokio::select! {
                    () = tokio::time::sleep(debounce) => break,
                    event = rx.recv() => if event.is_none() {
                        return;
                    },
                }
            }
            reload();
        }
    });

    Ok(watcher)
}

#[cfg(test)]
#[path = "watcher_test.rs"]
mod tests;
