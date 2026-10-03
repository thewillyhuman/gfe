//! The kernel program against a real kernel. Needs Linux and the privilege to
//! load eBPF; where it is refused, the test reports that and passes, since
//! there is nothing it could check.
#![cfg(target_os = "linux")]

use gfe_ebpf::{ClosedConnection, ClosedConnections, Ending, Origin, TcpProbe, Unavailable};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

/// Attach, or explain why this environment cannot.
fn attach() -> Option<(TcpProbe, ClosedConnections)> {
    match TcpProbe::attach(1024) {
        Ok(attached) => Some(attached),
        // Nothing to check without the privilege or the program. Anything
        // else, a program the kernel rejects in particular, is a failure.
        Err(reason @ (Unavailable::NotPermitted(_) | Unavailable::NotBuilt)) => {
            eprintln!("skipped: {reason}");
            None
        }
        Err(other) => panic!("{other}"),
    }
}

/// The reports for the two ends of one connection, in whichever order the
/// kernel delivers them: `(the end at first, the end at second)`.
async fn closed_ends(
    events: &mut ClosedConnections,
    first: SocketAddr,
    second: SocketAddr,
) -> (ClosedConnection, ClosedConnection) {
    let mut ends = std::collections::HashMap::new();
    while !(ends.contains_key(&first) && ends.contains_key(&second)) {
        let closed = tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .expect("the kernel should report the closed connection")
            .expect("the kernel side is attached");
        ends.insert(closed.local, closed);
    }
    (ends.remove(&first).unwrap(), ends.remove(&second).unwrap())
}

#[tokio::test]
async fn reports_both_ends_of_a_connection_closed_by_the_client() {
    let Some((probe, mut events)) = attach() else {
        return;
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = listener.local_addr().unwrap();

    // A client connects and sends five bytes; the server answers with three;
    // the client closes first.
    let mut client = TcpStream::connect(server_addr).unwrap();
    let client_addr = client.local_addr().unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let waited = probe.accept_queue_wait(server_addr, client_addr);
    let (mut server, _) = listener.accept().unwrap();
    client.write_all(b"hello").unwrap();
    let mut request = [0u8; 5];
    server.read_exact(&mut request).unwrap();
    server.write_all(b"bye").unwrap();
    let mut response = [0u8; 3];
    client.read_exact(&mut response).unwrap();
    drop(client);
    std::thread::sleep(Duration::from_millis(50));
    drop(server);

    let (accepted, connected) = closed_ends(&mut events, server_addr, client_addr).await;

    // The connection sat in the accept queue for the 50 ms before accept().
    let waited = waited.expect("the kernel knows the connection before it is accepted");
    assert!(waited >= Duration::from_millis(50), "{waited:?}");
    assert!(waited < Duration::from_secs(5), "{waited:?}");

    assert_eq!(accepted.peer, client_addr);
    assert_eq!(accepted.origin, Origin::Accepted);
    assert_eq!(accepted.ending, Ending::PeerClosed);
    // TCP counts the SYN and the FIN as one byte each, so the totals can
    // exceed the payload by up to two.
    assert!((5..=7).contains(&accepted.bytes_received), "{accepted:?}");
    assert!((3..=5).contains(&accepted.bytes_acked), "{accepted:?}");
    assert_eq!(accepted.retransmits, 0);
    assert!(
        accepted.lifetime >= Duration::from_millis(50),
        "{accepted:?}"
    );
    assert!(accepted.rtt > Duration::ZERO, "{accepted:?}");

    assert_eq!(connected.peer, server_addr);
    assert_eq!(connected.origin, Origin::Connected);
    assert_eq!(connected.ending, Ending::NodeClosed);
    assert!((3..=5).contains(&connected.bytes_received), "{connected:?}");
    assert_eq!(probe.lost_events(), 0);
}
