use super::*;
use crate::test_support::{PATIENCE, Recorder, closed_soon};
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
    let open = OpenConnections::new(limits.max_connections);
    let (drain, drain_rx) = watch::channel(false);
    let (cut, cut_rx) = watch::channel(false);
    let accept_loop = tokio::spawn(run_listener(
        serve,
        Arc::clone(&listener),
        socket,
        Arc::clone(&open),
        limits.max_connections_per_listener,
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
    assert_eq!(running.open.limit.in_use(), 1);
}

#[tokio::test]
async fn a_connection_over_the_per_listener_limit_is_closed_and_reported() {
    let (serve, mut record) = Recorder::holding();
    let limits = Limits {
        max_connections: 100,
        max_connections_per_listener: 1,
    };
    let running = accepting(serve, limits).await;
    let _served = TcpStream::connect(running.addr).await.unwrap();
    record.next_accepted().await;

    let mut beyond = TcpStream::connect(running.addr).await.unwrap();
    let refused = record.next_refused().await;

    assert_eq!(refused, ("web", Limit::MaxConnectionsPerListener));
    assert!(closed_soon(&mut beyond).await);
    assert_eq!(running.open.limit.in_use(), 1);
}

#[tokio::test]
async fn a_connection_over_the_total_limit_is_closed_and_reported() {
    let (serve, mut record) = Recorder::holding();
    let limits = Limits {
        max_connections: 1,
        max_connections_per_listener: 100,
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
async fn reports_a_refusal_with_the_listener_as_it_is_now() {
    let (serve, mut record) = Recorder::holding();
    let limits = Limits {
        max_connections: 100,
        max_connections_per_listener: 1,
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
}

#[tokio::test]
async fn a_cut_drops_the_connections_still_served() {
    let (serve, mut record) = Recorder::holding();
    let running = accepting(serve, generous()).await;
    let mut client = TcpStream::connect(running.addr).await.unwrap();
    record.next_accepted().await;

    running.cut.send_replace(true);

    assert!(closed_soon(&mut client).await);
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
