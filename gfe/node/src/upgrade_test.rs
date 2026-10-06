use super::*;
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::Instant;

fn listening() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").unwrap()
}

/// What runs as the successor here is this test binary, started again with
/// `--upgrade`: a flag the test harness refuses, so it exits at once and
/// with a failure, as a binary that cannot start does.
#[tokio::test]
async fn keeps_its_sockets_when_the_successor_cannot_start() {
    let socket = listening();
    let addr = socket.local_addr().unwrap();
    let duplicate = socket.try_clone().unwrap();

    let handed_over = hand_over(vec![(addr, duplicate)], None).await;

    let error = format!("{:#}", handed_over.unwrap_err());
    assert!(error.contains("could not be started"), "{error}");
    let client = TcpStream::connect(addr).unwrap();
    let (_, peer) = socket.accept().unwrap();
    assert_eq!(peer, client.local_addr().unwrap());
}

#[test]
fn releasing_the_predecessor_tells_it_this_node_accepts_connections() {
    let (outgoing, successor) = UnixStream::pair().unwrap();
    // Held open: macOS refuses a read timeout on a socket whose peer has
    // closed (EINVAL), and releasing closes the successor's end.
    let _still_open = successor.try_clone().unwrap();
    let predecessor = Predecessor { channel: successor };

    predecessor.release().unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    crate::handover::await_confirmation(&outgoing, deadline).unwrap();
}

#[test]
fn a_successor_that_does_not_answer_in_time_is_reported_with_the_bound() {
    let e = std::io::Error::from(std::io::ErrorKind::TimedOut);

    let reason = not_taken_over(e).to_string();

    assert_eq!(
        reason,
        "the successor did not accept connections within 60 s"
    );
}

#[test]
fn a_successor_that_went_away_is_reported_as_such() {
    let e = std::io::Error::from(std::io::ErrorKind::UnexpectedEof);

    let reason = not_taken_over(e).to_string();

    assert!(reason.contains("went away before it took over"), "{reason}");
}

#[test]
fn any_other_failure_keeps_its_cause() {
    let e = std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed handover");

    let reason = format!("{:#}", not_taken_over(e));

    assert_eq!(
        reason,
        "the successor did not take over: malformed handover"
    );
}
