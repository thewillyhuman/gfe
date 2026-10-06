use super::*;
use std::io::Write;
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

fn listening() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").unwrap()
}

/// A deadline far enough out that a test never reaches it.
fn soon() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

/// What a successor receives when it is sent `sockets`.
fn handed_over(sockets: &Sockets) -> Sockets {
    let (outgoing, successor) = UnixStream::pair().unwrap();
    send(&outgoing, sockets).unwrap();
    receive(&successor).unwrap()
}

#[test]
fn successor_accepts_on_the_sockets_it_is_given() {
    let socket = listening();
    let addr = socket.local_addr().unwrap();
    let configured_on: SocketAddr = "0.0.0.0:443".parse().unwrap();
    let sent = Sockets {
        listeners: vec![(configured_on, socket)],
        ops: None,
    };

    let mut received = handed_over(&sent);
    let (given_for, given) = received.listeners.pop().unwrap();
    let client = TcpStream::connect(addr).unwrap();
    let (_, peer) = given.accept().unwrap();

    assert_eq!(given_for, configured_on);
    assert_eq!(peer, client.local_addr().unwrap());
}

#[test]
fn tells_the_ops_socket_from_the_listeners() {
    let ops = listening();
    let ops_addr = ops.local_addr().unwrap();
    let sent = Sockets {
        listeners: vec![("127.0.0.1:80".parse().unwrap(), listening())],
        ops: Some((ops_addr, ops)),
    };

    let received = handed_over(&sent);
    let (given_for, given) = received.ops.unwrap();

    assert_eq!(given_for, ops_addr);
    assert_eq!(given.local_addr().unwrap(), ops_addr);
    assert_eq!(received.listeners.len(), 1);
}

#[test]
fn hands_over_more_sockets_than_one_message_carries() {
    let sockets: Vec<TcpListener> = (0..100).map(|_| listening()).collect();
    let bound: Vec<SocketAddr> = sockets.iter().map(|s| s.local_addr().unwrap()).collect();
    let sent = Sockets {
        listeners: bound.iter().copied().zip(sockets).collect(),
        ops: None,
    };

    let received = handed_over(&sent);

    let given: Vec<SocketAddr> = received
        .listeners
        .iter()
        .map(|(configured_on, socket)| {
            assert_eq!(socket.local_addr().unwrap(), *configured_on);
            *configured_on
        })
        .collect();
    assert_eq!(given, bound);
}

#[test]
fn refuses_a_handover_of_another_version() {
    let (mut outgoing, successor) = UnixStream::pair().unwrap();
    outgoing.write_all(b"gfe-handover 2\n").unwrap();
    outgoing.shutdown(Shutdown::Write).unwrap();

    let received = receive(&successor);

    assert_eq!(received.unwrap_err().kind(), io::ErrorKind::InvalidData);
}

#[test]
fn outgoing_node_learns_which_process_received_the_sockets() {
    let (outgoing, successor) = UnixStream::pair().unwrap();
    send(&outgoing, &Sockets::default()).unwrap();

    receive(&successor).unwrap();

    assert_eq!(
        await_receipt(&outgoing, soon()).unwrap(),
        std::process::id()
    );
}

#[test]
fn confirmation_is_not_lost_when_it_arrives_with_the_receipt() {
    let (outgoing, successor) = UnixStream::pair().unwrap();
    send(&outgoing, &Sockets::default()).unwrap();
    receive(&successor).unwrap();
    confirm(&successor).unwrap();

    await_receipt(&outgoing, soon()).unwrap();

    assert!(await_confirmation(&outgoing, soon()).is_ok());
}

#[test]
fn outgoing_node_learns_that_the_successor_is_ready() {
    let (outgoing, successor) = UnixStream::pair().unwrap();

    confirm(&successor).unwrap();

    assert!(await_confirmation(&outgoing, soon()).is_ok());
}

#[test]
fn outgoing_node_learns_that_the_successor_went_away() {
    let (outgoing, successor) = UnixStream::pair().unwrap();

    drop(successor);

    assert!(await_confirmation(&outgoing, soon()).is_err());
}

#[test]
fn outgoing_node_stops_waiting_at_the_deadline() {
    let (outgoing, _successor) = UnixStream::pair().unwrap();
    let deadline = Instant::now() + Duration::from_millis(50);

    let confirmed = await_confirmation(&outgoing, deadline);

    assert_eq!(confirmed.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert!(Instant::now() >= deadline);
}

#[test]
fn outgoing_node_does_not_wait_once_the_deadline_has_passed() {
    let (outgoing, mut successor) = UnixStream::pair().unwrap();
    successor.write_all(b"ready\n").unwrap();

    let confirmed = await_confirmation(&outgoing, Instant::now());

    assert_eq!(confirmed.unwrap_err().kind(), io::ErrorKind::TimedOut);
}

/// The receipt arriving late leaves the confirmation only what is left
/// of the time, not as much again.
#[test]
fn one_deadline_bounds_the_receipt_and_the_confirmation_together() {
    let (outgoing, mut successor) = UnixStream::pair().unwrap();
    let started = Instant::now();
    let deadline = started + Duration::from_millis(500);
    let late_receipt = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(400));
        successor.write_all(b"received 4242\n").unwrap();
        successor
    });

    await_receipt(&outgoing, deadline).unwrap();
    let confirmed = await_confirmation(&outgoing, deadline);

    assert_eq!(confirmed.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_millis(800));
    drop(late_receipt.join());
}

#[test]
fn outgoing_node_stops_waiting_when_it_shuts_the_channel_down() {
    let (outgoing, _successor) = UnixStream::pair().unwrap();
    let waiting = outgoing.try_clone().unwrap();
    let wait = std::thread::spawn(move || {
        let started = Instant::now();
        let confirmed = await_confirmation(&waiting, started + Duration::from_secs(30));
        (confirmed, started.elapsed())
    });
    std::thread::sleep(Duration::from_millis(100));

    outgoing.shutdown(Shutdown::Both).unwrap();
    let (confirmed, waited) = wait.join().unwrap();

    assert!(confirmed.is_err());
    assert!(waited < Duration::from_secs(5), "{waited:?}");
}
