//! Capturing what a test logs, for the tests of this crate that assert on
//! the events a node emits.
//!
//! One subscriber serves the whole test binary, and it can be installed
//! once: `tracing` caches per callsite whether anybody listens, so
//! subscribers that came and went per test could lose an event. Every test
//! that reads its log therefore goes through here, and gets the lines
//! emitted on its own thread. A `#[tokio::test]` runs its runtime, and so
//! everything it spawns, on that thread.
use std::cell::RefCell;
use std::sync::{Arc, Mutex, Once, PoisonError};

/// The log lines emitted on one thread while its test captures, as JSON.
#[derive(Clone, Default)]
pub(crate) struct Captured(Arc<Mutex<Vec<u8>>>);

thread_local! {
    /// Where the lines emitted on this thread go while a test captures.
    static CAPTURING: RefCell<Option<Captured>> = const { RefCell::new(None) };
}

/// Hands each log line to the test capturing on the thread that emitted it,
/// and drops the lines of threads where no test captures.
struct ToCapturingTest;

impl std::io::Write for ToCapturingTest {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        CAPTURING.with(|capturing| {
            if let Some(captured) = capturing.borrow().as_ref() {
                captured
                    .0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend_from_slice(buf);
            }
        });
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Stops capturing on this thread when dropped.
pub(crate) struct Capturing;

impl Drop for Capturing {
    fn drop(&mut self) {
        CAPTURING.with(|capturing| *capturing.borrow_mut() = None);
    }
}

impl Captured {
    /// Capture what is logged on this thread, at info and above, until the
    /// guard is dropped.
    pub(crate) fn start() -> (Captured, Capturing) {
        static SUBSCRIBER: Once = Once::new();
        SUBSCRIBER.call_once(|| {
            tracing_subscriber::fmt()
                .json()
                .with_max_level(tracing::Level::INFO)
                .with_writer(|| ToCapturingTest)
                .init();
        });
        let captured = Captured::default();
        CAPTURING.with(|capturing| *capturing.borrow_mut() = Some(captured.clone()));
        (captured, Capturing)
    }

    /// The fields of every event of `target` captured so far.
    pub(crate) fn events(&self, target: &str) -> Vec<serde_json::Value> {
        let raw = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        String::from_utf8_lossy(&raw)
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|event| event["target"] == target)
            .map(|event| event["fields"].clone())
            .collect()
    }
}
