use super::*;
use std::sync::mpsc;

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

/// A destination that keeps what it is given where the test can see it.
#[derive(Clone, Default)]
struct Collecting(Arc<std::sync::Mutex<Vec<u8>>>);

impl Write for Collecting {
    fn write(&mut self, line: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(line);
        Ok(line.len())
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

#[test]
fn dropping_a_destination_writes_out_what_is_queued() {
    let written = Collecting::default();
    let (mut writer, destination) = non_blocking("test", written.clone(), 8);

    for _ in 0..3 {
        writer.write_all(b"a line\n").unwrap();
    }
    drop(destination);

    assert_eq!(written.0.lock().unwrap().as_slice(), b"a line\n".repeat(3));
}

#[test]
fn traffic_events_are_the_ones_under_the_gfe_targets() {
    for target in ["gfe::access", "gfe::conn", "gfe::tcp"] {
        assert!(is_traffic(target), "{target}");
    }
    for target in ["gfe_core::server", "gfe_node", "pingora_core::protocols"] {
        assert!(!is_traffic(target), "{target}");
    }
}

/// Counts the events a filter lets through.
#[derive(Clone, Default)]
struct Counted(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Counted {
    fn on_event(&self, _: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// How many of `emit`'s events get through the filter built from `rust_log`.
fn let_through(rust_log: Option<&str>, emit: impl FnOnce()) -> usize {
    use tracing_subscriber::layer::SubscriberExt;

    let counted = Counted::default();
    let subscriber = tracing_subscriber::registry()
        .with(filter(rust_log))
        .with(counted.clone());
    tracing::subscriber::with_default(subscriber, emit);
    counted.0.load(std::sync::atomic::Ordering::Relaxed)
}

#[test]
fn logs_at_info_unless_told_otherwise() {
    let through = let_through(None, || {
        tracing::info!(target: "gfe_node", "ready");
        tracing::debug!(target: "gfe_node", "detail");
    });

    assert_eq!(through, 1);
}

#[test]
fn what_pingora_logs_about_a_client_that_misbehaves_is_off_by_default() {
    let through = let_through(None, || {
        tracing::error!(target: "pingora_proxy", "Fail to proxy: connection closed");
        tracing::error!(target: "pingora_core::apps", "H2 handshake error");
    });

    assert_eq!(through, 0);
}

#[test]
fn the_rest_of_what_pingora_logs_is_kept() {
    let through = let_through(None, || {
        tracing::warn!(target: "pingora_core::connectors", "something about a backend");
    });

    assert_eq!(through, 1);
}

#[test]
fn rust_log_turns_pingoras_lines_about_clients_back_on() {
    let through = let_through(Some("info,pingora_proxy=error"), || {
        tracing::error!(target: "pingora_proxy", "Fail to proxy: connection closed");
    });

    assert_eq!(through, 1);
}

#[test]
fn rust_log_sets_the_level_of_everything_else() {
    let through = let_through(Some("warn"), || {
        tracing::info!(target: "gfe_node", "ready");
        tracing::warn!(target: "gfe_node", "careful");
        tracing::error!(target: "pingora_proxy", "Fail to proxy: connection closed");
    });

    assert_eq!(through, 1);
}

#[test]
fn a_rust_log_that_cannot_be_parsed_falls_back_to_info() {
    let through = let_through(Some("not a level=="), || {
        tracing::info!(target: "gfe_node", "ready");
        tracing::debug!(target: "gfe_node", "detail");
    });

    assert_eq!(through, 1);
}
