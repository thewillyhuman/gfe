use super::*;
use std::io::Write;
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

const PROTOCOL: Protocol = Protocol {
    name: "example-handover",
    version: 1,
};

const ROLES: &[&str] = &["listener", "ops"];

fn listening() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").unwrap()
}

fn socket(role: &str, addr: SocketAddr, socket: TcpListener) -> Socket {
    Socket {
        role: role.to_string(),
        addr,
        socket,
    }
}

/// A deadline far enough out that a test never reaches it.
fn soon() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

/// What a successor receives when it is sent `sockets`.
fn handed_over(sockets: &[Socket]) -> Vec<Socket> {
    let (outgoing, successor) = UnixStream::pair().unwrap();
    send(&outgoing, &PROTOCOL, sockets).unwrap();
    receive(&successor, &PROTOCOL, ROLES).unwrap()
}

#[test]
fn successor_accepts_on_the_sockets_it_is_given() {
    let listener = listening();
    let addr = listener.local_addr().unwrap();
    let configured_on: SocketAddr = "0.0.0.0:443".parse().unwrap();

    let mut received = handed_over(&[socket("listener", configured_on, listener)]);
    let given = received.pop().unwrap();
    let client = TcpStream::connect(addr).unwrap();
    let (_, peer) = given.socket.accept().unwrap();

    assert_eq!(given.role, "listener");
    assert_eq!(given.addr, configured_on);
    assert_eq!(peer, client.local_addr().unwrap());
}

#[test]
fn every_socket_keeps_its_role_and_its_place() {
    let ops = listening();
    let ops_addr = ops.local_addr().unwrap();
    let sent = [
        socket("listener", "127.0.0.1:80".parse().unwrap(), listening()),
        socket("ops", ops_addr, ops),
    ];

    let received = handed_over(&sent);

    let roles: Vec<&str> = received.iter().map(|s| s.role.as_str()).collect();
    assert_eq!(roles, ["listener", "ops"]);
    assert_eq!(received[1].addr, ops_addr);
    assert_eq!(received[1].socket.local_addr().unwrap(), ops_addr);
}

#[test]
fn hands_over_more_sockets_than_one_message_carries() {
    let sent: Vec<Socket> = (0..100)
        .map(|_| {
            let listener = listening();
            socket("listener", listener.local_addr().unwrap(), listener)
        })
        .collect();
    let bound: Vec<SocketAddr> = sent.iter().map(|s| s.addr).collect();

    let received = handed_over(&sent);

    let given: Vec<SocketAddr> = received
        .iter()
        .map(|given| {
            assert_eq!(given.socket.local_addr().unwrap(), given.addr);
            given.addr
        })
        .collect();
    assert_eq!(given, bound);
}

/// A process of another release reads and writes exactly these bytes:
/// they must not change.
#[test]
fn the_exchange_is_a_header_then_a_line_per_socket() {
    let (outgoing, mut successor) = UnixStream::pair().unwrap();
    let sent = [
        socket("listener", "0.0.0.0:443".parse().unwrap(), listening()),
        socket("ops", "127.0.0.1:9101".parse().unwrap(), listening()),
    ];

    send(&outgoing, &PROTOCOL, &sent).unwrap();
    let mut text = String::new();
    successor.read_to_string(&mut text).unwrap();

    assert_eq!(
        text,
        "example-handover 1\nlistener 0.0.0.0:443\nops 127.0.0.1:9101\n"
    );
}

#[test]
fn refuses_a_handover_of_another_version() {
    let (mut outgoing, successor) = UnixStream::pair().unwrap();
    outgoing.write_all(b"example-handover 2\n").unwrap();
    outgoing.shutdown(Shutdown::Write).unwrap();

    let received = receive(&successor, &PROTOCOL, ROLES);

    assert_eq!(received.unwrap_err().kind(), io::ErrorKind::InvalidData);
}

#[test]
fn refuses_a_socket_of_a_role_it_does_not_know() {
    let (outgoing, successor) = UnixStream::pair().unwrap();
    let sent = [socket(
        "metrics",
        "127.0.0.1:80".parse().unwrap(),
        listening(),
    )];
    send(&outgoing, &PROTOCOL, &sent).unwrap();

    let received = receive(&successor, &PROTOCOL, ROLES);

    assert_eq!(received.unwrap_err().kind(), io::ErrorKind::InvalidData);
}

#[test]
fn refuses_to_send_a_role_that_is_not_one_word() {
    let (outgoing, _successor) = UnixStream::pair().unwrap();
    let sent = [socket(
        "two words",
        "127.0.0.1:80".parse().unwrap(),
        listening(),
    )];

    let sending = send(&outgoing, &PROTOCOL, &sent);

    assert_eq!(sending.unwrap_err().kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn outgoing_process_learns_which_process_received_the_sockets() {
    let (outgoing, successor) = UnixStream::pair().unwrap();
    send(&outgoing, &PROTOCOL, &[]).unwrap();

    receive(&successor, &PROTOCOL, ROLES).unwrap();

    assert_eq!(
        await_receipt(&outgoing, soon()).unwrap(),
        std::process::id()
    );
}

#[test]
fn confirmation_is_not_lost_when_it_arrives_with_the_receipt() {
    let (outgoing, successor) = UnixStream::pair().unwrap();
    send(&outgoing, &PROTOCOL, &[]).unwrap();
    receive(&successor, &PROTOCOL, ROLES).unwrap();
    confirm(&successor).unwrap();

    await_receipt(&outgoing, soon()).unwrap();

    assert!(await_confirmation(&outgoing, soon()).is_ok());
}

#[test]
fn outgoing_process_learns_that_the_successor_is_ready() {
    let (outgoing, successor) = UnixStream::pair().unwrap();

    confirm(&successor).unwrap();

    assert!(await_confirmation(&outgoing, soon()).is_ok());
}

#[test]
fn outgoing_process_learns_that_the_successor_went_away() {
    let (outgoing, successor) = UnixStream::pair().unwrap();

    drop(successor);

    assert!(await_confirmation(&outgoing, soon()).is_err());
}

#[test]
fn outgoing_process_stops_waiting_at_the_deadline() {
    let (outgoing, _successor) = UnixStream::pair().unwrap();
    let deadline = Instant::now() + Duration::from_millis(50);

    let confirmed = await_confirmation(&outgoing, deadline);

    assert_eq!(confirmed.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert!(Instant::now() >= deadline);
}

#[test]
fn outgoing_process_does_not_wait_once_the_deadline_has_passed() {
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
fn outgoing_process_stops_waiting_when_it_shuts_the_channel_down() {
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
