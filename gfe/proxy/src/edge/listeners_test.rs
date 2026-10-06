use super::*;
use crate::edge::test_support::{
    CapturedLogs, Describe, NAME, TestCert, acceptor, exchange, get, listener, read_until_closed,
    shared_with,
};
use gfe_config::{LimitsConfig, ListenProtocol, TimeoutsConfig};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A set of listeners serving [`Describe`], and what it is watched by.
struct Node {
    listeners: Listeners<Describe>,
    edge: Arc<Edge<Describe>>,
    handler: Arc<Describe>,
    drain: Drain,
}

impl Node {
    fn start(desired: &[Listener]) -> Self {
        Node::start_with(desired, TimeoutsConfig::default(), LimitsConfig::default())
    }

    fn start_with(desired: &[Listener], timeouts: TimeoutsConfig, limits: LimitsConfig) -> Self {
        let cert = TestCert::new(NAME);
        let (tls, resolver) = acceptor(&[&cert]);
        let handler = Arc::new(Describe::default());
        let shared = shared_with(timeouts, limits, resolver);
        let edge = Arc::new(Edge::new(shared, Arc::clone(&handler), tls).unwrap());
        let drain = Drain::new();
        let node = Node {
            listeners: Listeners::new(Arc::clone(&edge), &drain),
            edge,
            handler,
            drain,
        };
        node.reconcile(desired);
        node
    }

    fn reconcile(&self, desired: &[Listener]) {
        let staged = self.listeners.stage(desired).unwrap();
        self.listeners.commit(staged);
    }

    fn addr(&self, id: &str) -> SocketAddr {
        self.listeners
            .local_addr(&ListenerId(id.into()))
            .expect("the listener is running")
    }

    fn assert_metric(&self, expected: &str) {
        let metrics = self.edge.shared().metrics().encode();
        assert!(
            metrics.contains(expected),
            "missing {expected} in:\n{metrics}"
        );
    }
}

fn http_listener(id: &str) -> Listener {
    listener(id, ListenProtocol::Http)
}

/// A plaintext listener on a loopback port that was free a moment ago. A
/// listener is identified by the address it is configured on: two
/// listeners on port 0 would be one.
fn http_listener_on_free_port(id: &str) -> Listener {
    Listener {
        port: free_port(),
        ..http_listener(id)
    }
}

/// A loopback port that was free a moment ago.
fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    probe.local_addr().unwrap().port()
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

/// A connection that has been answered once and is still open; `None` if
/// the node closed it instead of serving it.
async fn try_open_connection(addr: SocketAddr) -> Option<TcpStream> {
    let mut stream = TcpStream::connect(addr).await.ok()?;
    stream.write_all(get("/").as_bytes()).await.ok()?;
    let mut received = [0u8; 4096];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut received))
        .await
        .expect("the node should answer a connection or close it")
        .ok()?;
    received[..read]
        .starts_with(b"HTTP/1.1 200")
        .then_some(stream)
}

// ---------------------------------------------------------------------------
// Reconciling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reconcile_binds_added_listener() {
    let node = Node::start(&[http_listener("kept")]);

    node.reconcile(&[http_listener("kept"), http_listener_on_free_port("added")]);
    let mut stream = TcpStream::connect(node.addr("added")).await.unwrap();
    let response = exchange(&mut stream, &get("/")).await;

    assert!(response.contains("listener=added"), "{response}");
}

#[tokio::test]
async fn reconcile_stops_removed_listener_and_keeps_serving_its_open_connection() {
    let node = Node::start(&[http_listener("kept"), http_listener_on_free_port("removed")]);
    let addr = node.addr("removed");
    let mut open = TcpStream::connect(addr).await.unwrap();
    exchange(&mut open, &get("/")).await;

    node.reconcile(&[http_listener("kept")]);
    let again = exchange(&mut open, &get("/again")).await;

    assert!(again.contains("path=/again"), "{again}");
    assert!(!accepts_connections(addr, false).await);
    assert_eq!(
        node.listeners.local_addr(&ListenerId("removed".into())),
        None
    );
}

#[tokio::test]
async fn reconcile_keeps_unchanged_listener_bound() {
    let node = Node::start(&[http_listener("http")]);
    let before = node.addr("http");

    node.reconcile(&[http_listener("http")]);

    // The config asks for port 0, so a rebind would land on another port.
    assert_eq!(node.addr("http"), before);
    assert!(accepts_connections(before, true).await);
}

#[tokio::test]
async fn a_renamed_listener_names_the_next_requests_without_rebinding() {
    let node = Node::start(&[http_listener("a")]);
    let addr = node.addr("a");
    let mut open = TcpStream::connect(addr).await.unwrap();
    exchange(&mut open, &get("/")).await;

    // Same address, so the same socket.
    node.reconcile(&[http_listener("renamed")]);
    let on_open = exchange(&mut open, &get("/")).await;
    let mut fresh = TcpStream::connect(addr).await.unwrap();
    let on_fresh = exchange(&mut fresh, &get("/")).await;

    assert_eq!(node.addr("renamed"), addr);
    assert_eq!(node.listeners.local_addr(&ListenerId("a".into())), None);
    assert!(on_open.contains("listener=renamed"), "{on_open}");
    assert!(on_fresh.contains("listener=renamed"), "{on_fresh}");
}

#[tokio::test]
async fn stage_fails_without_side_effects_when_address_is_taken() {
    let node = Node::start(&[http_listener("http")]);
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let unbindable = Listener {
        port: taken.local_addr().unwrap().port(),
        ..http_listener("unbindable")
    };

    let staged = node
        .listeners
        .stage(&[http_listener("renamed"), unbindable]);

    let error = staged.unwrap_err().to_string();
    assert!(error.contains("unbindable"), "{error}");
    assert_eq!(
        node.listeners.local_addr(&ListenerId("unbindable".into())),
        None
    );
    let mut stream = TcpStream::connect(node.addr("http")).await.unwrap();
    let response = exchange(&mut stream, &get("/")).await;
    assert!(response.contains("listener=http"), "{response}");
}

#[tokio::test]
async fn dropping_a_staged_config_closes_what_it_bound() {
    let node = Node::start(&[]);
    let port = free_port();
    let staged = node
        .listeners
        .stage(&[Listener {
            port,
            ..http_listener("http")
        }])
        .unwrap();

    drop(staged);

    // The port can be had again.
    std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
}

#[tokio::test]
async fn an_unchanged_listener_accepts_through_reloads_without_a_gap() {
    let node = Node::start(&[http_listener("a")]);
    let addr = node.addr("a");
    let extras = [
        http_listener_on_free_port("extra0"),
        http_listener_on_free_port("extra1"),
    ];
    let reloading = async {
        for i in 0..50 {
            node.reconcile(&[http_listener("a"), extras[i % 2].clone()]);
            tokio::task::yield_now().await;
        }
    };
    let connecting = async {
        for _ in 0..50 {
            let mut stream = TcpStream::connect(addr).await.expect("no gap in accepting");
            let response = exchange(&mut stream, &get("/")).await;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        }
    };

    tokio::join!(reloading, connecting);

    assert_eq!(node.addr("a"), addr);
}

// ---------------------------------------------------------------------------
// Which listener an address belongs to
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tells_which_listener_a_local_address_belongs_to() {
    let node = Node::start(&[http_listener("http")]);
    let bound = node.addr("http");
    let elsewhere = SocketAddr::new(bound.ip(), free_port());

    assert_eq!(
        node.listeners.listener_at(bound),
        Some(ListenerId("http".into()))
    );
    assert_eq!(node.listeners.listener_at(elsewhere), None);
}

#[tokio::test]
async fn an_ipv4_address_belongs_to_a_dual_stack_listener_on_its_port() {
    if std::net::TcpListener::bind("[::]:0").is_err() {
        // No IPv6 on this host.
        return;
    }
    let dual_stack = Listener {
        address: "::".parse().unwrap(),
        ..http_listener("any")
    };
    let node = Node::start(&[dual_stack]);
    let port = node.addr("any").port();

    let found = node
        .listeners
        .listener_at(SocketAddr::from(([127, 0, 0, 1], port)));

    assert_eq!(found, Some(ListenerId("any".into())));
}

// ---------------------------------------------------------------------------
// Handing the sockets over
// ---------------------------------------------------------------------------

#[tokio::test]
async fn listens_on_an_adopted_socket_instead_of_binding_its_address() {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let node = Node::start(&[]);

    node.listeners.adopt([(addr, socket)]);
    // Binding the same address again would fail: the socket is reused.
    node.reconcile(&[Listener {
        port: addr.port(),
        ..http_listener("http")
    }]);

    assert_eq!(node.addr("http"), addr);
}

#[tokio::test]
async fn closes_an_adopted_socket_that_no_listener_is_configured_on() {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let node = Node::start(&[]);

    node.listeners.adopt([(addr, socket)]);
    node.reconcile(&[http_listener("http")]);

    assert!(!accepts_connections(addr, false).await);
}

#[tokio::test]
async fn a_successor_serves_connections_on_the_sockets_it_adopts() {
    let first = Node::start(&[http_listener("a")]);
    let addr = first.addr("a");
    let sockets = first.listeners.sockets().unwrap();
    first.drain.trigger();
    first.listeners.serve_until_drained().await;
    // Waits in the socket's queue: served only if the successor accepts on
    // that very socket.
    let mut queued = TcpStream::connect(addr).await.unwrap();

    let successor = Node::start(&[]);
    successor.listeners.adopt(sockets);
    successor.reconcile(&[http_listener("a")]);
    let response = exchange(&mut queued, &get("/")).await;

    // Lent under the address its listener is configured on (port 0 here),
    // which is what a successor looks it up by.
    assert!(response.contains("listener=a"), "{response}");
    assert_eq!(successor.addr("a"), addr);
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

fn start_limited(limits: LimitsConfig) -> Node {
    Node::start_with(
        &[http_listener("a"), http_listener_on_free_port("b")],
        TimeoutsConfig::default(),
        limits,
    )
}

#[tokio::test]
async fn closes_connections_beyond_the_node_wide_limit() {
    let node = start_limited(LimitsConfig {
        max_connections: 1,
        ..Default::default()
    });
    let _held = try_open_connection(node.addr("a")).await.unwrap();

    let beyond = try_open_connection(node.addr("b")).await;

    assert!(beyond.is_none());
    node.assert_metric(r#"gfe_connections_rejected_total{reason="limit"} 1"#);
}

#[tokio::test]
async fn closes_connections_beyond_the_limit_of_a_listener() {
    let node = start_limited(LimitsConfig {
        max_connections_listener: 1,
        ..Default::default()
    });
    let _held = try_open_connection(node.addr("a")).await.unwrap();

    let beyond = try_open_connection(node.addr("a")).await;
    let elsewhere = try_open_connection(node.addr("b")).await;

    assert!(beyond.is_none());
    assert!(elsewhere.is_some());
    node.assert_metric(r#"gfe_connections_rejected_total{reason="limit"} 1"#);
}

#[tokio::test]
async fn a_closed_connection_makes_room_for_the_next() {
    let node = start_limited(LimitsConfig {
        max_connections: 1,
        ..Default::default()
    });
    let first = try_open_connection(node.addr("a")).await.unwrap();

    drop(first);

    // The node gives the place back once it has noticed the client is gone.
    let deadline = Instant::now() + Duration::from_secs(5);
    while try_open_connection(node.addr("a")).await.is_none() {
        assert!(Instant::now() < deadline, "the place was never given back");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ---------------------------------------------------------------------------
// Drain
// ---------------------------------------------------------------------------

fn start_draining_within(deadline_ms: u64) -> Node {
    Node::start_with(
        &[http_listener("http")],
        TimeoutsConfig {
            drain_deadline: Duration::from_millis(deadline_ms),
            ..Default::default()
        },
        LimitsConfig::default(),
    )
}

#[tokio::test]
async fn serve_until_drained_returns_at_once_without_connections() {
    let node = Node::start(&[http_listener("http")]);

    node.drain.trigger();
    let drained =
        tokio::time::timeout(Duration::from_secs(5), node.listeners.serve_until_drained()).await;

    assert_eq!(drained, Ok(Drained { cut: 0, stuck: 0 }));
}

#[tokio::test]
async fn a_draining_node_stops_accepting() {
    let node = Node::start(&[http_listener("http")]);
    let addr = node.addr("http");

    node.drain.trigger();
    node.listeners.serve_until_drained().await;

    assert!(TcpStream::connect(addr).await.is_err());
}

#[tokio::test]
async fn an_idle_connection_may_send_one_more_request_and_is_closed_after_it() {
    let node = start_draining_within(2_000);
    let mut stream = TcpStream::connect(node.addr("http")).await.unwrap();
    exchange(&mut stream, &get("/")).await;

    node.drain.trigger();
    stream.write_all(get("/last").as_bytes()).await.unwrap();
    let last = read_until_closed(&mut stream).await;

    assert!(last.contains("path=/last"), "{last}");
    assert!(
        last.to_ascii_lowercase().contains("connection: close"),
        "{last}"
    );
}

#[tokio::test]
async fn an_idle_connection_is_closed_half_way_through_the_drain() {
    let (logs, _capturing) = CapturedLogs::start();
    let node = start_draining_within(400);
    let mut stream = TcpStream::connect(node.addr("http")).await.unwrap();
    exchange(&mut stream, &get("/")).await;

    node.drain.trigger();
    let started = Instant::now();
    let rest = read_until_closed(&mut stream).await;

    let after = started.elapsed();
    assert_eq!(rest, "");
    assert!(after >= Duration::from_millis(180), "{after:?}");
    assert!(after < Duration::from_millis(400), "{after:?}");
    assert_eq!(logs.connection_event().await["reason"], "drain");
}

#[tokio::test]
async fn serve_until_drained_returns_as_soon_as_the_last_connection_is_gone() {
    let node = start_draining_within(10_000);
    let mut stream = TcpStream::connect(node.addr("http")).await.unwrap();
    exchange(&mut stream, &get("/")).await;

    node.drain.trigger();
    let started = Instant::now();
    let client_leaves = async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(stream);
    };
    let (drained, ()) = tokio::join!(node.listeners.serve_until_drained(), client_leaves);

    let after = started.elapsed();
    assert!(after < Duration::from_secs(2), "{after:?}");
    assert_eq!(drained, Drained { cut: 0, stuck: 0 });
    node.assert_metric("gfe_connections_active 0");
}

#[tokio::test]
async fn a_connection_still_open_at_the_deadline_is_cut_and_counted_as_shutdown() {
    let (logs, _capturing) = CapturedLogs::start();
    let node = start_draining_within(300);
    let mut stream = TcpStream::connect(node.addr("http")).await.unwrap();
    stream
        .write_all(get("/slow/10000").as_bytes())
        .await
        .unwrap();
    node.handler.until_busy_with(1).await;

    node.drain.trigger();
    let started = Instant::now();
    let drained = node.listeners.serve_until_drained().await;
    let returned_after = started.elapsed();
    let rest = read_until_closed(&mut stream).await;

    assert!(
        returned_after >= Duration::from_millis(290),
        "{returned_after:?}"
    );
    assert!(
        returned_after < Duration::from_millis(1_000),
        "{returned_after:?}"
    );
    assert_eq!(drained, Drained { cut: 1, stuck: 0 });
    assert_eq!(rest, "");
    assert_eq!(logs.connection_event().await["reason"], "shutdown");
    node.assert_metric(r#"gfe_connections_closed_total{listener="http",reason="shutdown"} 1"#);
    node.assert_metric("gfe_connections_active 0");
    assert_eq!(node.listeners.open_connections(), 0);
}
