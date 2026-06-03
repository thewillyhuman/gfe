//! inotify-based config file watcher with debounce.
//!
//! The watcher observes the config file's *parent directory* (robust against
//! editors/deploy tooling that replace the file via rename) and invokes a
//! caller-supplied reload closure after a debounce window. The reload closure
//! runs inside the Tokio runtime, so it may spawn tasks (e.g. health probes).

use gfe_types::GfeError;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

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
            if touches_config {
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
    use std::sync::atomic::{AtomicUsize, Ordering};

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
