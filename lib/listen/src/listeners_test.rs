use super::*;
use crate::accept::Limit;
use crate::test_support::{PATIENCE, Record, Recorder, closed_soon};
use tokio::net::TcpStream;

type Set = Listeners<&'static str, Recorder<&'static str>>;

const ANY_PORT: &str = "127.0.0.1:0";

fn generous() -> Limits {
    Limits {
        max_connections: 100,
        max_connections_per_listener: 100,
    }
}

/// An empty set whose connections are held until their clients close
/// them, what it reports, and its drain.
fn listeners() -> (Set, Record<&'static str>, Drain) {
    listeners_with(generous())
}

fn listeners_with(limits: Limits) -> (Set, Record<&'static str>, Drain) {
    let drain = Drain::new();
    let (serve, record) = Recorder::holding();
    (Listeners::new(serve, limits, &drain), record, drain)
}

fn addr(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

/// A loopback address whose port was free a moment ago.
fn free_addr() -> SocketAddr {
    let probe = std::net::TcpListener::bind(ANY_PORT).unwrap();
    probe.local_addr().unwrap()
}

fn reconcile(listeners: &Set, desired: &[(SocketAddr, &'static str)]) {
    let staged = listeners.stage(desired.to_vec()).unwrap();
    listeners.commit(staged);
}

/// Whether something accepts connections on `addr`, waiting up to a few
/// seconds for it to reach the `expected` state: a socket closes when the
/// task accepting on it is next scheduled, not at once.
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
    let (listeners, _, _drain) = listeners();
    reconcile(&listeners, &[(addr(ANY_PORT), "kept")]);

    let added = free_addr();
    reconcile(&listeners, &[(addr(ANY_PORT), "kept"), (added, "added")]);

    assert_eq!(listeners.local_addr(added), Some(added));
    assert!(accepts_connections(added, true).await);
}

#[tokio::test]
async fn reconcile_stops_removed_listener() {
    let (listeners, _, _drain) = listeners();
    let removed = free_addr();
    reconcile(
        &listeners,
        &[(addr(ANY_PORT), "kept"), (removed, "removed")],
    );
    assert!(accepts_connections(removed, true).await);

    reconcile(&listeners, &[(addr(ANY_PORT), "kept")]);

    assert!(!accepts_connections(removed, false).await);
    assert_eq!(listeners.local_addr(removed), None);
}

#[tokio::test]
async fn reconcile_keeps_unchanged_listener_bound() {
    let (listeners, _, _drain) = listeners();
    reconcile(&listeners, &[(addr(ANY_PORT), "http")]);
    let before = listeners.local_addr(addr(ANY_PORT)).unwrap();

    reconcile(&listeners, &[(addr(ANY_PORT), "http")]);

    // Configured on port 0, so a rebind would land on another port.
    assert_eq!(listeners.local_addr(addr(ANY_PORT)), Some(before));
    assert!(accepts_connections(before, true).await);
}

#[tokio::test]
async fn reconcile_replaces_what_is_attached_without_rebinding() {
    let (listeners, mut record, _drain) = listeners();
    reconcile(&listeners, &[(addr(ANY_PORT), "http")]);
    let before = listeners.local_addr(addr(ANY_PORT)).unwrap();
    let _early = TcpStream::connect(before).await.unwrap();
    let early = record.next_accepted().await;

    reconcile(&listeners, &[(addr(ANY_PORT), "renamed")]);
    let _late = TcpStream::connect(before).await.unwrap();
    let late = record.next_accepted().await;

    assert_eq!(listeners.local_addr(addr(ANY_PORT)), Some(before));
    assert_eq!(late.listener, "renamed");
    // A connection accepted before sees the change too.
    assert_eq!(**early.handle.load(), "renamed");
}

#[tokio::test]
async fn stage_fails_without_side_effects_when_address_is_taken() {
    let (listeners, _, _drain) = listeners();
    reconcile(&listeners, &[(addr(ANY_PORT), "running")]);
    let taken = std::net::TcpListener::bind(ANY_PORT).unwrap();
    let unbindable = taken.local_addr().unwrap();

    let staged = listeners.stage(vec![
        (addr(ANY_PORT), "running"),
        (unbindable, "unbindable"),
    ]);

    let error = staged.unwrap_err().to_string();
    assert!(error.contains(&unbindable.to_string()), "{error}");
    assert_eq!(listeners.local_addr(unbindable), None);
    let running = listeners.local_addr(addr(ANY_PORT)).unwrap();
    assert!(accepts_connections(running, true).await);
}

#[tokio::test]
async fn stage_refuses_an_address_named_twice() {
    let (listeners, _, _drain) = listeners();
    let twice = free_addr();

    let staged = listeners.stage(vec![(twice, "one"), (twice, "other")]);

    assert_eq!(staged.unwrap_err().kind(), io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn dropping_a_staged_config_closes_what_it_bound() {
    let (listeners, _, _drain) = listeners();
    let addr = free_addr();
    let staged = listeners.stage(vec![(addr, "http")]).unwrap();

    drop(staged);

    // The address can be had again.
    std::net::TcpListener::bind(addr).unwrap();
}

#[tokio::test]
async fn listens_on_an_adopted_socket_instead_of_binding_its_address() {
    let socket = std::net::TcpListener::bind(ANY_PORT).unwrap();
    let addr = socket.local_addr().unwrap();
    let (listeners, _, _drain) = listeners();

    listeners.adopt([(addr, socket)]);
    // Binding the same address again would fail: the socket is reused.
    reconcile(&listeners, &[(addr, "http")]);

    assert_eq!(listeners.local_addr(addr), Some(addr));
}

#[tokio::test]
async fn closes_an_adopted_socket_that_no_listener_is_configured_on() {
    let socket = std::net::TcpListener::bind(ANY_PORT).unwrap();
    let addr = socket.local_addr().unwrap();
    let (listeners, _, _drain) = listeners();

    listeners.adopt([(addr, socket)]);
    reconcile(&listeners, &[(self::addr(ANY_PORT), "http")]);

    assert!(!accepts_connections(addr, false).await);
}

#[tokio::test]
async fn lends_its_sockets_which_outlive_it() {
    let (listeners, _, drain) = listeners();
    reconcile(&listeners, &[(addr(ANY_PORT), "http")]);
    let bound = listeners.local_addr(addr(ANY_PORT)).unwrap();

    let mut lent = listeners.sockets().unwrap();
    drain.trigger();
    listeners.serve_until_drained(PATIENCE).await;
    drop(listeners);
    let (configured_on, socket) = lent.pop().unwrap();
    let client = TcpStream::connect(bound).await.unwrap();
    // The lent socket shares its non-blocking mode with the one the set
    // accepted on, and a client's connect can return a moment before the
    // connection is in the queue: wait for it rather than race it.
    socket.set_nonblocking(false).unwrap();
    let (_, peer) = socket.accept().unwrap();

    // Lent under the address its listener is configured on (port 0 here),
    // which is what a successor looks it up by.
    assert_eq!(configured_on, addr(ANY_PORT));
    assert_eq!(peer, client.local_addr().unwrap());
}

#[tokio::test]
async fn tells_what_is_attached_to_the_listener_of_a_local_address() {
    let (listeners, _, _drain) = listeners();
    reconcile(&listeners, &[(addr(ANY_PORT), "http")]);
    let bound = listeners.local_addr(addr(ANY_PORT)).unwrap();
    let elsewhere = SocketAddr::new(bound.ip(), free_addr().port());

    assert_eq!(listeners.listener_at(bound).as_deref(), Some(&"http"));
    assert_eq!(listeners.listener_at(elsewhere), None);
}

#[tokio::test]
async fn an_ipv4_address_belongs_to_a_dual_stack_listener_on_its_port() {
    let (listeners, _, _drain) = listeners();
    let any = addr("[::]:0");
    let Ok(staged) = listeners.stage(vec![(any, "any")]) else {
        // No IPv6 on this host.
        return;
    };
    listeners.commit(staged);
    let port = listeners.local_addr(any).unwrap().port();

    let found = listeners.listener_at(SocketAddr::from(([127, 0, 0, 1], port)));

    assert_eq!(found.as_deref(), Some(&"any"));
}

#[tokio::test]
async fn each_listener_has_a_cap_of_its_own() {
    let limits = Limits {
        max_connections: 100,
        max_connections_per_listener: 1,
    };
    let (listeners, mut record, _drain) = listeners_with(limits);
    let (one, other) = (free_addr(), free_addr());
    reconcile(&listeners, &[(one, "one"), (other, "other")]);

    let _first = TcpStream::connect(one).await.unwrap();
    record.next_accepted().await;
    let _second = TcpStream::connect(other).await.unwrap();
    record.next_accepted().await;
    let mut beyond = TcpStream::connect(one).await.unwrap();

    assert_eq!(
        record.next_refused().await,
        ("one", Limit::MaxConnectionsPerListener)
    );
    assert!(closed_soon(&mut beyond).await);
    assert_eq!(listeners.open_connections(), 2);
}

#[tokio::test]
async fn the_total_cap_spans_every_listener() {
    let limits = Limits {
        max_connections: 1,
        max_connections_per_listener: 100,
    };
    let (listeners, mut record, _drain) = listeners_with(limits);
    let (one, other) = (free_addr(), free_addr());
    reconcile(&listeners, &[(one, "one"), (other, "other")]);

    let _first = TcpStream::connect(one).await.unwrap();
    record.next_accepted().await;
    let _beyond = TcpStream::connect(other).await.unwrap();

    assert_eq!(
        record.next_refused().await,
        ("other", Limit::MaxConnections)
    );
}

#[tokio::test]
async fn a_removed_listener_leaves_its_connections_open() {
    let (listeners, mut record, _drain) = listeners();
    let removed = free_addr();
    reconcile(&listeners, &[(removed, "removed")]);
    let _client = TcpStream::connect(removed).await.unwrap();
    record.next_accepted().await;

    reconcile(&listeners, &[]);

    assert!(!accepts_connections(removed, false).await);
    assert_eq!(listeners.open_connections(), 1);
}

#[tokio::test]
async fn serve_until_drained_returns_at_once_without_connections() {
    let (listeners, _, drain) = listeners();
    reconcile(&listeners, &[(addr(ANY_PORT), "http")]);

    drain.trigger();
    let drained = tokio::time::timeout(PATIENCE, listeners.serve_until_drained(PATIENCE)).await;

    assert_eq!(drained, Ok(Drained { cut: 0, stuck: 0 }));
}

#[tokio::test]
async fn draining_stops_accepting() {
    let (listeners, _, drain) = listeners();
    reconcile(&listeners, &[(addr(ANY_PORT), "http")]);
    let bound = listeners.local_addr(addr(ANY_PORT)).unwrap();

    drain.trigger();
    listeners.serve_until_drained(PATIENCE).await;

    assert!(TcpStream::connect(bound).await.is_err());
    assert_eq!(listeners.local_addr(addr(ANY_PORT)), None);
}

#[tokio::test]
async fn serve_until_drained_returns_when_the_last_connection_ends() {
    let (listeners, mut record, drain) = listeners();
    reconcile(&listeners, &[(addr(ANY_PORT), "http")]);
    let bound = listeners.local_addr(addr(ANY_PORT)).unwrap();
    let client = TcpStream::connect(bound).await.unwrap();
    record.next_accepted().await;
    drain.trigger();

    let draining = listeners.serve_until_drained(Duration::from_secs(60));
    tokio::pin!(draining);
    let before_the_client_left =
        tokio::time::timeout(Duration::from_millis(20), draining.as_mut()).await;
    drop(client);
    let drained = tokio::time::timeout(PATIENCE, draining).await;

    assert!(before_the_client_left.is_err());
    assert_eq!(drained, Ok(Drained { cut: 0, stuck: 0 }));
}

#[tokio::test]
async fn serve_until_drained_cuts_what_is_left_at_the_deadline() {
    let (listeners, mut record, drain) = listeners();
    reconcile(&listeners, &[(addr(ANY_PORT), "http")]);
    let bound = listeners.local_addr(addr(ANY_PORT)).unwrap();
    let mut client = TcpStream::connect(bound).await.unwrap();
    record.next_accepted().await;

    drain.trigger();
    let drained = listeners
        .serve_until_drained(Duration::from_millis(20))
        .await;

    assert_eq!(drained, Drained { cut: 1, stuck: 0 });
    assert!(closed_soon(&mut client).await);
    assert_eq!(listeners.open_connections(), 0);
}

#[tokio::test]
async fn dropping_the_set_closes_its_sockets() {
    let (listeners, _, _drain) = listeners();
    reconcile(&listeners, &[(addr(ANY_PORT), "http")]);
    let bound = listeners.local_addr(addr(ANY_PORT)).unwrap();

    drop(listeners);

    assert!(!accepts_connections(bound, false).await);
}
