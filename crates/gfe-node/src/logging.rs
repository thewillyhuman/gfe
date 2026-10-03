//! The node's log, and the guarantee that writing it never holds up a
//! request.
//!
//! An event is formatted where it happens and handed to a queue; a thread of
//! its own writes the queue out. A destination that takes lines more slowly
//! than the node produces them fills the queue, and from then on lines are
//! dropped instead of making whoever logs wait. Dropped lines are counted
//! (`gfe_log_lost_lines`), so that a log with holes in it is known to have
//! them.

use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing_appender::non_blocking::{ErrorCounter, NonBlocking, NonBlockingBuilder, WorkerGuard};

/// How many lines may wait to be written to one destination before more are
/// dropped. At some 500 bytes a line this is at most about 64 MB.
const QUEUE_LINES: usize = 128_000;

/// The node's log. Dropping it writes out what is still queued, so it is
/// kept until the process exits.
pub struct Log {
    destinations: Vec<Destination>,
}

impl Log {
    /// Start logging: from here on events go to standard output, as JSON
    /// lines, filtered by `RUST_LOG` (default `info`).
    pub fn start() -> Log {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        use tracing_subscriber::{fmt, EnvFilter};

        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let (stdout, destination) = non_blocking("stdout", io::stdout(), QUEUE_LINES);
        tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt::layer()
                    .json()
                    .with_current_span(false)
                    .with_writer(stdout),
            )
            .init();
        Log {
            destinations: vec![destination],
        }
    }

    /// How many lines each destination has lost so far, by its name.
    pub fn lost_lines(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        self.destinations
            .iter()
            .map(|destination| (destination.name, destination.lost_lines()))
    }
}

/// One place log lines are written to, by a thread of its own.
struct Destination {
    name: &'static str,
    /// Lines dropped because the queue was full.
    dropped: ErrorCounter,
    /// Lines the destination did not accept.
    refused: Arc<AtomicU64>,
    /// Keeps the writing thread alive; writes out the queue when dropped.
    _worker: WorkerGuard,
}

impl Destination {
    /// Lines that were logged but never written.
    fn lost_lines(&self) -> u64 {
        self.dropped.dropped_lines() as u64 + self.refused.load(Ordering::Relaxed)
    }
}

/// A writer that queues up to `queue_lines` lines for `destination` and
/// never waits for it, and the handle that counts what did not make it.
fn non_blocking<W: Write + Send + 'static>(
    name: &'static str,
    destination: W,
    queue_lines: usize,
) -> (NonBlocking, Destination) {
    let refused = Arc::new(AtomicU64::new(0));
    let (writer, worker) = NonBlockingBuilder::default()
        .lossy(true)
        .buffered_lines_limit(queue_lines)
        .thread_name(&format!("gfe-log-{name}"))
        .finish(CountingRefusals {
            destination,
            refused: refused.clone(),
        });
    let destination = Destination {
        name,
        dropped: writer.error_counter(),
        refused,
        _worker: worker,
    };
    (writer, destination)
}

/// Writes lines to `destination` and counts the ones it does not accept: the
/// writing thread has nobody to report a failed write to.
struct CountingRefusals<W> {
    destination: W,
    refused: Arc<AtomicU64>,
}

impl<W: Write> Write for CountingRefusals<W> {
    fn write(&mut self, line: &[u8]) -> io::Result<usize> {
        self.destination.write(line)
    }

    /// Called once per line.
    fn write_all(&mut self, line: &[u8]) -> io::Result<()> {
        self.destination.write_all(line).inspect_err(|_| {
            self.refused.fetch_add(1, Ordering::Relaxed);
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        self.destination.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// A destination that takes nothing until the test lets go of it.
    struct Stalled(mpsc::Receiver<()>);

    impl Write for Stalled {
        fn write(&mut self, line: &[u8]) -> io::Result<usize> {
            let _ = self.0.recv();
            Ok(line.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A destination that takes nothing at all.
    struct Refusing;

    impl Write for Refusing {
        fn write(&mut self, _line: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("no space left"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_destination_that_stalls_does_not_hold_up_whoever_logs() {
        let (release, stalled) = mpsc::channel();
        let (mut writer, destination) = non_blocking("test", Stalled(stalled), 8);
        let (done, logged) = mpsc::channel();

        std::thread::spawn(move || {
            for _ in 0..100 {
                writer.write_all(b"a line\n").unwrap();
            }
            done.send(()).unwrap();
        });
        let logged_in_time = logged.recv_timeout(Duration::from_secs(5)).is_ok();
        let lost = destination.lost_lines();
        drop(release);

        assert!(logged_in_time, "logging waited for the destination");
        // Eight lines wait in the queue and one is with the destination.
        assert!(lost >= 90, "{lost} lines lost");
    }

    #[test]
    fn lines_a_destination_refuses_are_counted_as_lost() {
        let (mut writer, destination) = non_blocking("test", Refusing, 8);

        for _ in 0..3 {
            writer.write_all(b"a line\n").unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while destination.lost_lines() < 3 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(destination.lost_lines(), 3);
    }
}
