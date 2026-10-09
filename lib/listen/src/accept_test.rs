use super::*;
use crate::test_support::{PATIENCE, Recorder, closed_soon};
use std::num::{NonZeroU32, NonZeroUsize};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

/// An accept loop on a fresh loopback socket, and what it needs to be
/// driven: its address, the drain and cut signals, the open connections.
struct Running {
    addr: SocketAddr,
    listener: Arc<ArcSwap<&'static str>>,
    open: Arc<OpenConnections>,
    drain: watch::Sender<bool>,
    cut: watch::Sender<bool>,
    accept_loop: JoinHandle<()>,
}

/// Start accepting for `serve`, under `limits`, on a listener carrying
/// `"web"`.
async fn accepting<S: Serve<&'static str>>(serve: Arc<S>, limits: Limits) -> Running {
    let socket = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    let listener = Arc::new(ArcSwap::from_pointee("web"));
    let admission = Admission::new(limits);
    let open = Arc::clone(&admission.open);
    let (drain, drain_rx) = watch::channel(false);
    let (cut, cut_rx) = watch::channel(false);
    let accept_loop = tokio::spawn(run_listener(
        serve,
        Arc::clone(&listener),
        socket,
        admission,
        drain_rx,
        cut_rx,
    ));
    Running {
        addr,
        listener,
        open,
        drain,
        cut,
        accept_loop,
    }
}

fn generous() -> Limits {
    Limits {
        max_connections: 100,
        max_connections_per_listener: 100,
        connections_per_peer: None,
    }
}

/// `generous`, with each peer allowed `per_second` new connections a
/// second and as many at once.
fn per_peer(per_second: u32) -> Limits {
    Limits {
        connections_per_peer: Some(PeerRate {
            per_second: NonZeroU32::new(per_second).unwrap(),
            burst: NonZeroU32::new(per_second).unwrap(),
            tracked_peers: NonZeroUsize::new(100).unwrap(),
        }),
        ..generous()
    }
}

#[tokio::test]
async fn hands_each_connection_to_serve_with_its_listener_and_addresses() {
    let (serve, mut record) = Recorder::holding();
    let running = accepting(serve, generous()).await;

    let client = TcpStream::connect(running.addr).await.unwrap();
    let seen = record.next_accepted().await;

    assert_eq!(seen.listener, "web");
    assert_eq!(seen.peer, client.local_addr().unwrap());
    assert_eq!(seen.local, running.addr);
    assert!(Arc::ptr_eq(&seen.handle, &running.listener));
    assert_eq!(running.open.count(), 1);
}

#[tokio::test]
async fn a_connection_over_the_per_listener_limit_is_closed_and_reported() {
    let (serve, mut record) = Recorder::holding();
    let limits = Limits {
        max_connections: 100,
        max_connections_per_listener: 1,
        connections_per_peer: None,
    };
    let running = accepting(serve, limits).await;
    let _served = TcpStream::connect(running.addr).await.unwrap();
    record.next_accepted().await;

    let mut beyond = TcpStream::connect(running.addr).await.unwrap();
    let refused = record.next_refused().await;

    assert_eq!(refused, ("web", Limit::MaxConnectionsPerListener));
    assert!(closed_soon(&mut beyond).await);
    assert_eq!(running.open.count(), 1);
}

#[tokio::test]
async fn a_connection_over_the_total_limit_is_closed_and_reported() {
    let (serve, mut record) = Recorder::holding();
    let limits = Limits {
        max_connections: 1,
        max_connections_per_listener: 100,
        connections_per_peer: None,
    };
    let running = accepting(serve, limits).await;
    let _served = TcpStream::connect(running.addr).await.unwrap();
    record.next_accepted().await;

    let mut beyond = TcpStream::connect(running.addr).await.unwrap();
    let refused = record.next_refused().await;

    assert_eq!(refused, ("web", Limit::MaxConnections));
    assert!(closed_soon(&mut beyond).await);
}

#[tokio::test]
async fn a_closed_connection_makes_room_under_the_limit() {
    let (serve, mut record) = Recorder::holding();
    let limits = Limits {
        max_connections: 1,
        max_connections_per_listener: 1,
        connections_per_peer: None,
    };
    let running = accepting(serve, limits).await;
    let first = TcpStream::connect(running.addr).await.unwrap();
    record.next_accepted().await;

    drop(first);
    tokio::time::timeout(PATIENCE, running.open.all_closed())
        .await
        .unwrap();
    let second = TcpStream::connect(running.addr).await.unwrap();
    let seen = record.next_accepted().await;

    assert_eq!(seen.peer, second.local_addr().unwrap());
}

#[tokio::test]
async fn a_peer_over_its_connection_rate_is_closed_and_reported() {
    let (serve, mut record) = Recorder::holding();
    let running = accepting(serve, per_peer(1)).await;
    let _first = TcpStream::connect(running.addr).await.unwrap();
    record.next_accepted().await;

    let mut beyond = TcpStream::connect(running.addr).await.unwrap();
    let refused = record.next_refused().await;

    assert_eq!(refused, ("web", Limit::ConnectionsPerPeer));
    assert!(closed_soon(&mut beyond).await);
    assert_eq!(running.open.count(), 1);
}

#[tokio::test]
async fn a_peer_within_its_rate_is_served() {
    let (serve, mut record) = Recorder::holding();
    let running = accepting(serve, per_peer(2)).await;

    let first = TcpStream::connect(running.addr).await.unwrap();
    let second = TcpStream::connect(running.addr).await.unwrap();
    let seen_first = record.next_accepted().await;
    let seen_second = record.next_accepted().await;

    let mut served = [seen_first.peer, seen_second.peer];
    served.sort();
    let mut opened = [first.local_addr().unwrap(), second.local_addr().unwrap()];
    opened.sort();
    assert_eq!(served, opened);
}

#[tokio::test]
async fn reports_a_refusal_with_the_listener_as_it_is_now() {
    let (serve, mut record) = Recorder::holding();
    let limits = Limits {
        max_connections: 100,
        max_connections_per_listener: 1,
        connections_per_peer: None,
    };
    let running = accepting(serve, limits).await;
    let _served = TcpStream::connect(running.addr).await.unwrap();
    record.next_accepted().await;

    running.listener.store(Arc::new("renamed"));
    let _beyond = TcpStream::connect(running.addr).await.unwrap();

    assert_eq!(record.next_refused().await.0, "renamed");
}

#[tokio::test]
async fn stops_accepting_when_the_process_drains_and_tells_its_connections() {
    let (serve, mut record) = Recorder::leaving();
    let running = accepting(serve, generous()).await;
    let mut client = TcpStream::connect(running.addr).await.unwrap();
    record.next_accepted().await;

    running.drain.send_replace(true);
    let stopped = tokio::time::timeout(PATIENCE, running.accept_loop).await;

    assert!(stopped.is_ok());
    // The recorder leaves when it sees the drain.
    assert!(closed_soon(&mut client).await);
    tokio::time::timeout(PATIENCE, running.open.all_closed())
        .await
        .unwrap();
}

#[tokio::test]
async fn a_cut_drops_the_connections_still_served() {
    let (serve, mut record) = Recorder::holding();
    let running = accepting(serve, generous()).await;
    let mut client = TcpStream::connect(running.addr).await.unwrap();
    record.next_accepted().await;

    running.cut.send_replace(true);

    assert!(closed_soon(&mut client).await);
    tokio::time::timeout(PATIENCE, running.open.all_closed())
        .await
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn pause_lasts_its_whole_length_without_a_drain() {
    let (_tx, mut drain) = watch::channel(false);
    let started = tokio::time::Instant::now();

    let drained = pause_unless_drained(&mut drain, Duration::from_millis(50)).await;

    assert!(!drained);
    assert!(started.elapsed() >= Duration::from_millis(50));
}

#[tokio::test(start_paused = true)]
async fn pause_ends_as_soon_as_the_process_drains() {
    let (tx, mut drain) = watch::channel(false);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        tx.send_replace(true);
    });
    let started = tokio::time::Instant::now();

    let drained = pause_unless_drained(&mut drain, Duration::from_secs(60)).await;

    assert!(drained);
    assert!(started.elapsed() < Duration::from_secs(60));
}

#[tokio::test]
async fn no_open_connection_is_waited_for_at_once() {
    let open = OpenConnections::new(10);

    let waited = tokio::time::timeout(PATIENCE, open.all_closed()).await;

    assert!(waited.is_ok());
}

#[tokio::test]
async fn the_last_connection_to_close_ends_the_wait() {
    let open = OpenConnections::new(10);
    let slot = Slot {
        permits: Some((
            open.limit.try_acquire().unwrap(),
            ConcurrencyLimit::new(None).try_acquire().unwrap(),
        )),
        open: Arc::clone(&open),
    };
    assert_eq!(open.count(), 1);
    let (closing_tx, closing) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = closing.await;
        drop(slot);
    });

    let wait = open.all_closed();
    tokio::pin!(wait);
    let waited_before = tokio::time::timeout(Duration::from_millis(10), wait.as_mut()).await;
    closing_tx.send(()).unwrap();
    let waited = tokio::time::timeout(PATIENCE, wait).await;

    assert!(waited_before.is_err());
    assert!(waited.is_ok());
    assert_eq!(open.count(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_cut_is_signalled_when_it_is_sent_and_never_without_a_sender() {
    let (tx, mut cut) = watch::channel(false);
    tx.send_replace(true);
    let signalled = tokio::time::timeout(PATIENCE, cut_signalled(&mut cut)).await;
    let (tx, mut orphan) = watch::channel(false);
    drop(tx);
    let orphaned = tokio::time::timeout(PATIENCE, cut_signalled(&mut orphan)).await;

    assert!(signalled.is_ok());
    assert!(orphaned.is_err());
}

#[tokio::test]
async fn serve_plain_serves_up_to_its_cap_and_stops_when_told() {
    let socket = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    let (serve, mut record) = Recorder::leaving();
    let (stop, stopped) = watch::channel(false);
    let serving = tokio::spawn(serve_plain(socket, "ops", serve, 1, stopped));
    let mut held = TcpStream::connect(addr).await.unwrap();
    record.next_accepted().await;

    let mut beyond = TcpStream::connect(addr).await.unwrap();
    let refused = record.next_refused().await;
    stop.send_replace(true);
    let returned = tokio::time::timeout(PATIENCE, serving).await;

    assert_eq!(refused, ("ops", Limit::MaxConnections));
    assert!(closed_soon(&mut beyond).await);
    assert!(returned.is_ok());
    // Still served after the loop returned: it saw the signal and left.
    assert!(closed_soon(&mut held).await);
}
