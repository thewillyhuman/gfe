use super::*;
use tokio::net::TcpSocket;

/// The options of a peer for one attempt, armed under `cap`.
fn attempt(cap: &Arc<ConnectionCap>) -> PeerOptions {
    let mut options = PeerOptions::new();
    cap.arm(&mut options);
    options
}

/// Run the hook Pingora runs on the socket of a new connection.
fn open_socket(options: &PeerOptions) -> pingora_error::Result<()> {
    let hook = options.upstream_tcp_sock_tweak_hook.as_ref().unwrap();
    hook(&TcpSocket::new_v4().unwrap())
}

#[test]
fn takes_a_place_for_each_new_connection() {
    let cap = ConnectionCap::new(2, Gauge::default());
    let options = attempt(&cap);

    open_socket(&options).unwrap();

    assert_eq!(cap.in_use(), 1);
}

#[test]
fn refuses_a_new_connection_beyond_the_cap() {
    let cap = ConnectionCap::new(1, Gauge::default());
    let first = attempt(&cap);
    open_socket(&first).unwrap();
    let second = attempt(&cap);

    let refused = open_socket(&second).unwrap_err();

    assert_eq!(*refused.etype(), CONNECTION_LIMIT);
    assert_eq!(cap.in_use(), 1);
}

#[test]
fn gives_the_place_back_when_an_attempt_never_connected() {
    let cap = ConnectionCap::new(1, Gauge::default());
    let failed = attempt(&cap);
    open_socket(&failed).unwrap();

    drop(failed);

    assert_eq!(cap.in_use(), 0);
}

#[test]
fn an_established_connection_keeps_its_place_until_it_closes() {
    let open = Gauge::default();
    let cap = ConnectionCap::new(1, open.clone());
    let options = attempt(&cap);
    open_socket(&options).unwrap();
    // What Pingora does with an established connection: keep a clone of
    // the tracer in it, and tell it.
    let connection = options.tracer.clone().unwrap();
    connection.0.on_connected();
    drop(options);
    assert_eq!(cap.in_use(), 1);
    assert_eq!(open.get(), 1);

    connection.0.on_disconnected();
    drop(connection);

    assert_eq!(cap.in_use(), 0);
    assert_eq!(open.get(), 0);
}

#[test]
fn an_attempt_without_a_new_connection_takes_no_place() {
    let cap = ConnectionCap::new(1, Gauge::default());

    let _reusing = attempt(&cap);

    assert_eq!(cap.in_use(), 0);
}
