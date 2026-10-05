use super::*;
use crate::listener::test_support::{acceptor, shared};
use async_trait::async_trait;
use gfe_config::{ListenProtocol, TimeoutsConfig};
use pingora_core::protocols::Stream;
use pingora_core::server::ShutdownWatch;
use tokio::net::TcpStream;

/// An application that hangs up on every connection.
struct HangUp;

#[async_trait]
impl ServerApp for HangUp {
    async fn process_new(self: &Arc<Self>, _stream: Stream, _: &ShutdownWatch) -> Option<Stream> {
        None
    }
}

fn http_listener(id: &str, port: u16) -> Listener {
    Listener {
        id: ListenerId(id.into()),
        address: "127.0.0.1".parse().unwrap(),
        port,
        protocol: ListenProtocol::Http,
    }
}

/// A loopback port that was free a moment ago.
fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    probe.local_addr().unwrap().port()
}

/// An empty set, and the sender of its shutdown signal.
fn listeners() -> (Listeners<HangUp>, watch::Sender<bool>) {
    let (tx, shutdown) = watch::channel(false);
    let (tls, _) = acceptor(&[]);
    let listeners = Listeners::new(
        shared(TimeoutsConfig::default()),
        Arc::new(HangUp),
        tls,
        Connections::new(),
        shutdown,
    );
    (listeners, tx)
}

fn reconcile(listeners: &Listeners<HangUp>, desired: &[Listener]) {
    let staged = listeners.stage(desired).unwrap();
    listeners.commit(staged);
}

/// Whether something accepts connections on `addr`, waiting up to a few
/// seconds for it to reach the `expected` state.
async fn accepts_connections(addr: SocketAddr, expected: bool) -> bool {
    for _ in 0..100 {
        if TcpStream::connect(addr).await.is_ok() == expected {
            return expected;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    !expected
}

#[tokio::test]
async fn reconcile_binds_added_listener() {
    let (listeners, _tx) = listeners();
    let kept = http_listener("kept", 0);
    reconcile(&listeners, std::slice::from_ref(&kept));

    let added = http_listener("added", free_port());
    reconcile(&listeners, &[kept, added.clone()]);

    let addr = listeners.local_addr(&added.id).unwrap();
    assert!(accepts_connections(addr, true).await);
}

#[tokio::test]
async fn reconcile_stops_removed_listener() {
    let (listeners, _tx) = listeners();
    let kept = http_listener("kept", 0);
    let removed = http_listener("removed", free_port());
    reconcile(&listeners, &[kept.clone(), removed.clone()]);
    let addr = listeners.local_addr(&removed.id).unwrap();
    assert!(accepts_connections(addr, true).await);

    reconcile(&listeners, &[kept]);

    assert!(!accepts_connections(addr, false).await);
    assert_eq!(listeners.local_addr(&removed.id), None);
}

#[tokio::test]
async fn reconcile_keeps_unchanged_listener_bound() {
    let (listeners, _tx) = listeners();
    let listener = http_listener("http", 0);
    reconcile(&listeners, std::slice::from_ref(&listener));
    let before = listeners.local_addr(&listener.id).unwrap();

    reconcile(&listeners, std::slice::from_ref(&listener));

    // The config asks for port 0, so a rebind would land on another port.
    assert_eq!(listeners.local_addr(&listener.id), Some(before));
    assert!(accepts_connections(before, true).await);
}

#[tokio::test]
async fn reconcile_renames_a_listener_without_rebinding() {
    let (listeners, _tx) = listeners();
    let listener = http_listener("http", 0);
    reconcile(&listeners, std::slice::from_ref(&listener));
    let before = listeners.local_addr(&listener.id).unwrap();

    let renamed = http_listener("renamed", 0);
    reconcile(&listeners, std::slice::from_ref(&renamed));

    assert_eq!(listeners.local_addr(&renamed.id), Some(before));
    assert_eq!(listeners.local_addr(&listener.id), None);
}

#[tokio::test]
async fn stage_fails_without_side_effects_when_address_is_taken() {
    let (listeners, _tx) = listeners();
    let running = http_listener("http", 0);
    reconcile(&listeners, std::slice::from_ref(&running));
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let unbindable = http_listener("unbindable", taken.local_addr().unwrap().port());

    let staged = listeners.stage(&[running.clone(), unbindable.clone()]);

    let error = staged.unwrap_err().to_string();
    assert!(error.contains("unbindable"), "{error}");
    assert_eq!(listeners.local_addr(&unbindable.id), None);
    let addr = listeners.local_addr(&running.id).unwrap();
    assert!(accepts_connections(addr, true).await);
}

#[tokio::test]
async fn dropping_a_staged_config_closes_what_it_bound() {
    let (listeners, _tx) = listeners();
    let port = free_port();
    let staged = listeners.stage(&[http_listener("http", port)]).unwrap();

    drop(staged);

    // The port can be had again.
    std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
}

#[tokio::test]
async fn listens_on_an_adopted_socket_instead_of_binding_its_address() {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let (listeners, _tx) = listeners();

    listeners.adopt([(addr, socket)]);
    // Binding the same address again would fail: the socket is reused.
    reconcile(&listeners, &[http_listener("http", addr.port())]);

    assert_eq!(listeners.local_addr(&ListenerId("http".into())), Some(addr));
}

#[tokio::test]
async fn closes_an_adopted_socket_that_no_listener_is_configured_on() {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let (listeners, _tx) = listeners();

    listeners.adopt([(addr, socket)]);
    reconcile(&listeners, &[http_listener("http", 0)]);

    assert!(!accepts_connections(addr, false).await);
}

#[tokio::test]
async fn lends_its_sockets_which_outlive_it() {
    let (listeners, shutdown) = listeners();
    reconcile(&listeners, &[http_listener("http", 0)]);
    let addr = listeners.local_addr(&ListenerId("http".into())).unwrap();

    let mut lent = listeners.sockets().unwrap();
    shutdown.send_replace(true);
    listeners.serve_until_drained().await;
    let (configured_on, socket) = lent.pop().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    // The lent socket shares its non-blocking mode with the one the set
    // accepted on, and a client's connect can return a moment before the
    // connection is in the queue: wait for it rather than race it.
    socket.set_nonblocking(false).unwrap();
    let (_, peer) = socket.accept().unwrap();

    // Lent under the address its listener is configured on (port 0 here),
    // which is what a successor looks it up by.
    assert_eq!(configured_on, "127.0.0.1:0".parse().unwrap());
    assert_eq!(peer, client.local_addr().unwrap());
}

#[tokio::test]
async fn tells_which_listener_a_local_address_belongs_to() {
    let (listeners, _tx) = listeners();
    let listener = http_listener("http", 0);
    reconcile(&listeners, std::slice::from_ref(&listener));
    let bound = listeners.local_addr(&listener.id).unwrap();
    let elsewhere = SocketAddr::new(bound.ip(), free_port());

    assert_eq!(listeners.listener_at(bound), Some(listener.id.clone()));
    assert_eq!(listeners.listener_at(elsewhere), None);
}

#[tokio::test]
async fn an_ipv4_address_belongs_to_a_dual_stack_listener_on_its_port() {
    let (listeners, _tx) = listeners();
    let mut listener = http_listener("any", 0);
    listener.address = "::".parse().unwrap();
    if listeners.stage(std::slice::from_ref(&listener)).is_err() {
        // No IPv6 on this host.
        return;
    }
    reconcile(&listeners, std::slice::from_ref(&listener));
    let port = listeners.local_addr(&listener.id).unwrap().port();

    let found = listeners.listener_at(SocketAddr::from(([127, 0, 0, 1], port)));

    assert_eq!(found, Some(listener.id));
}

#[tokio::test]
async fn serve_until_drained_returns_at_once_without_connections() {
    let (listeners, shutdown) = listeners();
    reconcile(&listeners, &[http_listener("http", 0)]);

    shutdown.send_replace(true);
    let drained =
        tokio::time::timeout(Duration::from_secs(5), listeners.serve_until_drained()).await;

    assert!(drained.is_ok());
}
