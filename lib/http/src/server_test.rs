use super::*;
use crate::body::empty;

fn options() -> Options {
    Options {
        header_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(75),
        keep_alive_timeout: Duration::from_secs(20),
        drain_idle_grace: Duration::from_secs(5),
        max_header_bytes: 16 * 1024,
        max_concurrent_streams: 100,
    }
}

/// Answers every request with an empty `200`.
struct Empty;

impl Handler for Empty {
    async fn handle(&self, _request: Request<Incoming>) -> Response<BoxBody> {
        Response::new(empty())
    }
}

#[test]
fn accepts_options_within_their_limits() {
    assert_eq!(options().validate(), Ok(()));
}

#[test]
fn rejects_a_timeout_of_zero() {
    let options = Options {
        keep_alive_timeout: Duration::ZERO,
        ..options()
    };

    assert_eq!(
        options.validate(),
        Err(InvalidOptions::ZeroDuration("keep_alive_timeout"))
    );
}

#[test]
fn rejects_a_header_limit_below_the_minimum() {
    let options = Options {
        max_header_bytes: MIN_HEADER_BYTES - 1,
        ..options()
    };

    assert_eq!(
        options.validate(),
        Err(InvalidOptions::HeaderBytesTooSmall(MIN_HEADER_BYTES - 1))
    );
}

#[test]
fn rejects_room_for_no_stream() {
    let options = Options {
        max_concurrent_streams: 0,
        ..options()
    };

    assert_eq!(options.validate(), Err(InvalidOptions::NoStreams));
}

#[tokio::test]
async fn closes_a_connection_served_with_invalid_options_at_once() {
    let (_client, server) = tokio::io::duplex(1024);
    let (_drain, drain_rx) = watch::channel(false);
    let options = Options {
        max_header_bytes: 1024,
        ..options()
    };

    let closed = serve(server, Arc::new(Empty), options, drain_rx).await;

    assert_eq!(closed.reason, CloseReason::Error);
    assert_eq!(closed.requests, 0);
    let error = closed.error.unwrap();
    assert!(error.contains("max_header_bytes"), "{error}");
}

#[test]
fn a_connection_timed_out_by_the_transport_is_unresponsive() {
    let error = std::io::Error::from(std::io::ErrorKind::TimedOut);

    assert_eq!(
        error_close_reason(&error, false),
        CloseReason::ClientUnresponsive
    );
}

#[test]
fn a_reset_connection_is_a_client_abort() {
    let error = std::io::Error::from(std::io::ErrorKind::ConnectionReset);

    assert_eq!(error_close_reason(&error, true), CloseReason::ClientAbort);
}

/// An error caused by an I/O error, as hyper's and h2's are.
#[derive(Debug)]
struct CausedBy(std::io::Error);

impl std::fmt::Display for CausedBy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "caused by {}", self.0)
    }
}

impl std::error::Error for CausedBy {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[test]
fn an_io_error_found_among_the_causes_decides_the_reason() {
    let error = CausedBy(std::io::Error::from(std::io::ErrorKind::BrokenPipe));

    assert_eq!(error_close_reason(&error, false), CloseReason::ClientAbort);
}

#[test]
fn an_error_of_unknown_kind_is_an_error() {
    let error = std::fmt::Error;

    assert_eq!(error_close_reason(&error, false), CloseReason::Error);
}

#[test]
fn an_interrupted_read_is_a_cancelled_connection() {
    let error = std::io::Error::new(std::io::ErrorKind::Interrupted, "Cancelled");

    assert!(is_cancelled(&error));
}

#[test]
fn a_reset_is_not_a_cancelled_connection() {
    let error = std::io::Error::from(std::io::ErrorKind::ConnectionReset);

    assert!(!is_cancelled(&error));
}

#[test]
fn a_sender_gone_means_draining() {
    let (drain, drain_rx) = watch::channel(false);

    drop(drain);

    assert!(is_draining(&drain_rx));
}

#[test]
fn a_drain_not_yet_asked_for_is_not_draining() {
    let (_drain, drain_rx) = watch::channel(false);

    assert!(!is_draining(&drain_rx));
}
