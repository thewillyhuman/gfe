use super::*;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};

fn listening() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").unwrap()
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
fn the_sockets_stay_open_on_the_outgoing_node() {
    let socket = listening();
    let addr = socket.local_addr().unwrap();
    let sent = Sockets {
        listeners: vec![(addr, socket)],
        ops: None,
    };

    let received = handed_over(&sent);
    drop(received);
    let client = TcpStream::connect(addr).unwrap();
    let (_, peer) = sent.listeners[0].1.accept().unwrap();

    assert_eq!(peer, client.local_addr().unwrap());
}

/// What a `v1.1.0` node sends and expects, byte for byte.
#[test]
fn speaks_the_exchange_of_released_nodes() {
    let (outgoing, mut successor) = UnixStream::pair().unwrap();
    let sent = Sockets {
        listeners: vec![("0.0.0.0:443".parse().unwrap(), listening())],
        ops: Some(("127.0.0.1:9101".parse().unwrap(), listening())),
    };

    send(&outgoing, &sent).unwrap();
    let mut text = String::new();
    successor.read_to_string(&mut text).unwrap();

    assert_eq!(
        text,
        "gfe-handover 1\nlistener 0.0.0.0:443\nops 127.0.0.1:9101\n"
    );
}

#[test]
fn refuses_a_handover_of_another_version() {
    let (mut outgoing, successor) = UnixStream::pair().unwrap();
    outgoing.write_all(b"gfe-handover 2\n").unwrap();
    outgoing.shutdown(Shutdown::Write).unwrap();

    let received = receive(&successor);

    assert_eq!(received.unwrap_err().kind(), io::ErrorKind::InvalidData);
}
