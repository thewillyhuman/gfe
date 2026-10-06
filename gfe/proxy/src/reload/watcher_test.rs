use super::*;
use crate::reload::test_support::scratch_dir;
use notify::event::{CreateKind, DataChange, MetadataKind, RenameMode};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

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

/// Wait until `count` reaches at least `expected`, failing after a few
/// seconds.
async fn wait_for_reloads(count: &AtomicUsize, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while count.load(Ordering::SeqCst) < expected {
        assert!(Instant::now() < deadline, "no reload");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A reload that counts how many times it ran, reading `file` first.
fn counting_reload(file: std::path::PathBuf) -> (Arc<AtomicUsize>, impl Fn() + Send + 'static) {
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    (count, move || {
        let _ = std::fs::read(&file);
        counted.fetch_add(1, Ordering::SeqCst);
    })
}

#[tokio::test]
async fn reloads_when_the_file_is_written() {
    let file = scratch_dir("watch-write").join("dynamic.json");
    std::fs::write(&file, b"{}").unwrap();
    let (count, reload) = counting_reload(file.clone());
    let _watcher = watch(&file, Duration::from_millis(20), reload).unwrap();

    std::fs::write(&file, br#"{"x":1}"#).unwrap();

    wait_for_reloads(&count, 1).await;
}

#[tokio::test]
async fn reloads_when_another_file_is_renamed_over_it() {
    let dir = scratch_dir("watch-rename");
    let file = dir.join("dynamic.json");
    std::fs::write(&file, b"{}").unwrap();
    let (count, reload) = counting_reload(file.clone());
    let _watcher = watch(&file, Duration::from_millis(20), reload).unwrap();

    std::fs::write(dir.join("dynamic.json.staged"), br#"{"x":1}"#).unwrap();
    std::fs::rename(dir.join("dynamic.json.staged"), &file).unwrap();

    wait_for_reloads(&count, 1).await;
}

/// The reload reads the file it watches. On Linux that read is itself
/// reported by the watcher, and must not start another reload.
#[tokio::test]
async fn a_reload_that_reads_the_file_does_not_trigger_itself() {
    let file = scratch_dir("watch-loop").join("dynamic.json");
    std::fs::write(&file, b"{}").unwrap();
    let (count, reload) = counting_reload(file.clone());
    let _watcher = watch(&file, Duration::from_millis(20), reload).unwrap();

    std::fs::write(&file, br#"{"x":1}"#).unwrap();
    wait_for_reloads(&count, 1).await;
    // Absence cannot be polled for: give a loop the time to show.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // One change, one reload; a platform may report the write as two
    // events far enough apart for a second one. A loop would be dozens.
    let reloads = count.load(Ordering::SeqCst);
    assert!((1..=2).contains(&reloads), "reloaded {reloads} times");
}

#[tokio::test]
async fn writes_in_quick_succession_are_one_reload() {
    let file = scratch_dir("watch-debounce").join("dynamic.json");
    std::fs::write(&file, b"{}").unwrap();
    let (count, reload) = counting_reload(file.clone());
    let _watcher = watch(&file, Duration::from_millis(300), reload).unwrap();

    for i in 0..5 {
        std::fs::write(&file, format!(r#"{{"x":{i}}}"#)).unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    wait_for_reloads(&count, 1).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn other_files_of_the_directory_are_ignored() {
    let dir = scratch_dir("watch-other");
    let file = dir.join("dynamic.json");
    std::fs::write(&file, b"{}").unwrap();
    let (count, reload) = counting_reload(file.clone());
    let _watcher = watch(&file, Duration::from_millis(20), reload).unwrap();

    std::fs::write(dir.join("config-cache.json"), b"{}").unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_dropped_watcher_reloads_no_more() {
    let file = scratch_dir("watch-drop").join("dynamic.json");
    std::fs::write(&file, b"{}").unwrap();
    let (count, reload) = counting_reload(file.clone());
    let watcher = watch(&file, Duration::from_millis(20), reload).unwrap();

    drop(watcher);
    std::fs::write(&file, br#"{"x":1}"#).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_directory_that_does_not_exist_cannot_be_watched() {
    let file = std::env::temp_dir().join("gfe-core-no-such-dir/dynamic.json");

    let error = watch(&file, Duration::from_millis(20), || {}).unwrap_err();

    assert!(
        error.to_string().contains("gfe-core-no-such-dir"),
        "{error}"
    );
}
