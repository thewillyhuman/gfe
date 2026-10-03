//! The node's log: where it goes, and the guarantee that writing it never
//! holds up a request.
//!
//! An event is formatted where it happens and handed to a queue; a thread of
//! its own writes the queue out. A destination that takes lines more slowly
//! than the node produces them fills the queue, and from then on lines are
//! dropped instead of making whoever logs wait. Dropped lines are counted
//! (`gfe_log_lost_lines`), so that a log with holes in it is known to have
//! them.
//!
//! There are two destinations. Standard output always is one: it is what a
//! service manager collects. A file is the other, if the config names one
//! (`[log] file`); it then gets every line, and standard output keeps only
//! the node's own log. The events that describe traffic, one per request and
//! per connection, are too many for a service manager's journal and go to the
//! file alone.

use anyhow::{Context, Result};
use gfe_types::LogConfig;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing_appender::non_blocking::{ErrorCounter, NonBlocking, NonBlockingBuilder, WorkerGuard};

/// How many lines may wait to be written to one destination before more are
/// dropped. At some 500 bytes a line this is at most about 64 MB.
const QUEUE_LINES: usize = 128_000;

/// How often the log file is checked for having been rotated away.
const ROTATION_CHECK: Duration = Duration::from_secs(1);

/// The prefix of the targets of the events that describe traffic:
/// `gfe::access`, `gfe::conn`, `gfe::tcp`. The node's own events carry the
/// name of the module they come from.
const TRAFFIC_TARGETS: &str = "gfe::";

/// The node's log. Dropping it writes out what is still queued, so it is
/// kept until the process exits.
pub struct Log {
    destinations: Vec<Destination>,
}

impl Log {
    /// Start logging: from here on events are written as JSON lines,
    /// filtered by `RUST_LOG` (default `info`), to standard output and to
    /// the file `config` names, if any. Fails if that file cannot be opened.
    pub fn start(config: &LogConfig) -> Result<Log> {
        use tracing_subscriber::filter::filter_fn;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        use tracing_subscriber::{fmt, EnvFilter, Layer};

        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let mut destinations = Vec::new();

        let file = config
            .file
            .as_deref()
            .map(|path| {
                LogFile::open(path, ROTATION_CHECK)
                    .with_context(|| format!("opening the log file {}", path.display()))
            })
            .transpose()?;
        let has_file = file.is_some();
        let to_file = file.map(|file| {
            let (writer, destination) = non_blocking("file", file, QUEUE_LINES);
            destinations.push(destination);
            fmt::layer()
                .json()
                .with_current_span(false)
                .with_writer(writer)
        });

        let (writer, destination) = non_blocking("stdout", io::stdout(), QUEUE_LINES);
        destinations.push(destination);
        let to_stdout = fmt::layer()
            .json()
            .with_current_span(false)
            .with_writer(writer)
            .with_filter(filter_fn(move |event| {
                !(has_file && event.target().starts_with(TRAFFIC_TARGETS))
            }));

        tracing_subscriber::registry()
            .with(filter)
            .with(to_file)
            .with(to_stdout)
            .init();
        if let Some(path) = &config.file {
            tracing::info!(
                file = %path.display(),
                "requests and connections are logged to the file, not here"
            );
        }
        Ok(Log { destinations })
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

/// A file that log lines are appended to, and that is found again after it
/// has been rotated: whoever rotates it renames or removes it, and the lines
/// must go on at the path, not into the file that was moved away. A file
/// truncated in place needs nothing, since it is only ever appended to.
struct LogFile {
    path: PathBuf,
    file: File,
    recheck_every: Duration,
    checked_at: Instant,
    /// Set while the file at `path` is known not to be the one that is open
    /// and could not be opened either.
    misplaced: bool,
}

impl LogFile {
    /// Open the file at `path` for appending, creating it if it is not
    /// there. Whether it is still at `path` is looked at every
    /// `recheck_every`.
    fn open(path: &Path, recheck_every: Duration) -> io::Result<LogFile> {
        Ok(LogFile {
            path: path.to_path_buf(),
            file: Self::open_at(path)?,
            recheck_every,
            checked_at: Instant::now(),
            misplaced: false,
        })
    }

    fn open_at(path: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        // The log holds the addresses of clients and what they asked for:
        // not for everyone on the host to read.
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o640);
        options.open(path)
    }

    /// Whether the file that is open is still the one at `path`.
    #[cfg(unix)]
    fn in_place(&self) -> bool {
        use std::os::unix::fs::MetadataExt;
        match (std::fs::metadata(&self.path), self.file.metadata()) {
            (Ok(at_path), Ok(open)) => at_path.dev() == open.dev() && at_path.ino() == open.ino(),
            _ => false,
        }
    }

    #[cfg(not(unix))]
    fn in_place(&self) -> bool {
        self.path.exists()
    }
}

impl Write for LogFile {
    fn write(&mut self, line: &[u8]) -> io::Result<usize> {
        if self.misplaced || self.checked_at.elapsed() >= self.recheck_every {
            self.checked_at = Instant::now();
            if self.misplaced || !self.in_place() {
                // Until the file can be opened at its path every line fails,
                // and is counted: lines written to a file that was moved
                // away would be lines nobody finds.
                self.misplaced = true;
                self.file = Self::open_at(&self.path)?;
                self.misplaced = false;
            }
        }
        self.file.write(line)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// A path for a log file that only this test uses.
    fn log_path(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gfe-log-{}-{test}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("gfe.log");
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn log_file_keeps_what_was_written_to_it_before() {
        let path = log_path("append");
        std::fs::write(&path, "from an earlier run\n").unwrap();

        let mut log = LogFile::open(&path, Duration::ZERO).unwrap();
        log.write_all(b"from this run\n").unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(written, "from an earlier run\nfrom this run\n");
    }

    #[test]
    fn log_file_goes_on_at_its_path_after_being_rotated_away() {
        let path = log_path("rotated");
        let rotated = path.with_extension("log.1");
        let mut log = LogFile::open(&path, Duration::ZERO).unwrap();
        log.write_all(b"before\n").unwrap();

        std::fs::rename(&path, &rotated).unwrap();
        log.write_all(b"after\n").unwrap();

        assert_eq!(std::fs::read_to_string(&rotated).unwrap(), "before\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "after\n");
    }

    #[cfg(unix)]
    #[test]
    fn log_file_is_not_readable_by_everyone() {
        use std::os::unix::fs::PermissionsExt;
        let path = log_path("mode");

        LogFile::open(&path, Duration::ZERO).unwrap();

        // It holds the addresses of clients and what they asked for.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o007, 0, "mode {mode:o}");
    }

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
