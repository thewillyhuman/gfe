use super::*;
use crate::listener::stream::WireEnd;
use crate::listener::test_support::tcp_pair;
use gfe_config::{ListenProtocol, ListenerId};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn probes_a_peer_silent_for_client_idle() {
    let keepalive = tcp_keepalive(Duration::from_secs(42));

    assert_eq!(keepalive.idle, Duration::from_secs(42));
}

#[test]
fn gives_up_on_a_dead_peer_within_client_idle() {
    let keepalive = tcp_keepalive(Duration::from_secs(40));

    // Three probes ten seconds apart: gone for 30 s after the 40 s of
    // silence, not for the kernel's default of many minutes.
    assert_eq!(keepalive.interval, Duration::from_secs(10));
    assert_eq!(keepalive.count, 3);
}

#[test]
fn never_asks_the_kernel_for_less_than_a_second() {
    let keepalive = tcp_keepalive(Duration::from_millis(200));

    assert_eq!(keepalive.idle, Duration::from_secs(1));
    assert_eq!(keepalive.interval, Duration::from_secs(1));
}

#[tokio::test]
async fn the_kernel_takes_the_keepalive_of_an_accepted_socket() {
    let (_client, server) = tcp_pair().await;
    let mut l4 = L4Stream::from(server);

    // A no-op outside Linux; on Linux, the options are set for real.
    let set = l4.set_keepalive(&tcp_keepalive(Duration::from_secs(75)));

    assert!(set.is_ok(), "{set:?}");
}

#[test]
fn reports_an_ipv4_client_of_a_dual_stack_socket_as_ipv4() {
    let mapped: SocketAddr = "[::ffff:192.0.2.1]:40000".parse().unwrap();
    let v6: SocketAddr = "[2001:db8::1]:40000".parse().unwrap();

    assert_eq!(canonical(mapped), "192.0.2.1:40000".parse().unwrap());
    assert_eq!(canonical(v6), v6);
}

#[tokio::test]
async fn the_transport_stream_names_both_ends_of_the_connection() {
    let (_client, server) = tcp_pair().await;
    let client: SocketAddr = "192.0.2.1:40000".parse().unwrap();
    let local: SocketAddr = "192.0.2.2:443".parse().unwrap();

    let l4 = l4_stream(server, client, local);

    let digest = l4.get_socket_digest().unwrap();
    assert_eq!(digest.peer_addr().and_then(|a| a.as_inet()), Some(&client));
    assert_eq!(digest.local_addr().and_then(|a| a.as_inet()), Some(&local));
}

/// A connection being watched: its stream, its record of requests, the
/// client's end, the node's drain signal and the connection's own.
struct Watched {
    stream: ClientStream,
    state: Arc<StreamState>,
    conn: Arc<ConnInfo>,
    client: TcpStream,
    drain: watch::Sender<bool>,
    leave: watch::Receiver<bool>,
}

async fn watched(timeouts: TimeoutsConfig) -> Watched {
    let (client, server) = tcp_pair().await;
    let state = Arc::new(StreamState::default());
    let wire = Metered::new(
        L4Stream::from(server),
        Arc::clone(&state),
        Counter::default(),
        Counter::default(),
    );
    let conn = ConnInfo::new(
        client.local_addr().unwrap(),
        client.peer_addr().unwrap(),
        Arc::new(ArcSwap::from_pointee(Listener {
            id: ListenerId("http".into()),
            address: "127.0.0.1".parse().unwrap(),
            port: 0,
            protocol: ListenProtocol::Http,
        })),
        None,
    );
    let (drain, shutdown) = watch::channel(false);
    let (leave_tx, leave) = watch::channel(false);
    let watchdog_conn = Arc::clone(&conn);
    let watchdog_state = Arc::clone(&state);
    tokio::spawn(async move {
        watchdog(
            &watchdog_conn,
            &watchdog_state,
            &timeouts,
            shutdown,
            &leave_tx,
        )
        .await
    });
    Watched {
        stream: ClientStream::plain(wire),
        state,
        conn,
        client,
        drain,
        leave,
    }
}

fn timeouts(request_header_ms: u64, client_idle_ms: u64) -> TimeoutsConfig {
    TimeoutsConfig {
        request_header: Duration::from_millis(request_header_ms),
        client_idle: Duration::from_millis(client_idle_ms),
        drain_deadline: Duration::from_millis(200),
        ..Default::default()
    }
}

/// Read from `stream` until the read fails, waiting at most a few seconds.
async fn read_until_failure(stream: &mut ClientStream) -> (io::Error, Duration) {
    let started = Instant::now();
    let mut buf = [0u8; 64];
    let failure = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Err(e) = stream.read(&mut buf).await {
                return e;
            }
        }
    })
    .await
    .expect("the connection should have been cut");
    (failure, started.elapsed())
}

#[tokio::test]
async fn the_first_request_must_arrive_within_request_header() {
    let mut watched = watched(timeouts(100, 10_000)).await;

    let (failure, after) = read_until_failure(&mut watched.stream).await;

    assert_eq!(failure.kind(), io::ErrorKind::TimedOut);
    assert!(after >= Duration::from_millis(90), "{after:?}");
    assert_eq!(watched.state.expiry(), Some(Expiry::Header));
    assert_eq!(watched.state.end(), None);
}

#[tokio::test]
async fn a_connection_idle_after_its_request_is_cut_after_client_idle() {
    let mut watched = watched(timeouts(10_000, 100)).await;
    drop(watched.conn.begin_request());

    let (failure, after) = read_until_failure(&mut watched.stream).await;

    assert_eq!(failure.kind(), io::ErrorKind::TimedOut);
    assert!(after >= Duration::from_millis(90), "{after:?}");
    assert_eq!(watched.state.expiry(), Some(Expiry::Idle));
}

#[tokio::test]
async fn a_request_in_flight_is_never_cut() {
    let mut watched = watched(timeouts(50, 50)).await;
    let request = watched.conn.begin_request();

    let read = tokio::time::timeout(
        Duration::from_millis(300),
        watched.stream.read(&mut [0u8; 8]),
    )
    .await;
    drop(request);
    let (failure, _) = read_until_failure(&mut watched.stream).await;

    assert!(read.is_err(), "the read should still be waiting: {read:?}");
    assert_eq!(failure.kind(), io::ErrorKind::TimedOut);
    assert_eq!(watched.state.expiry(), Some(Expiry::Idle));
}

#[tokio::test]
async fn data_sent_in_time_is_read() {
    let mut watched = watched(timeouts(200, 10_000)).await;

    watched.client.write_all(b"GET").await.unwrap();
    let mut received = [0u8; 3];
    watched.stream.read_exact(&mut received).await.unwrap();

    assert_eq!(&received, b"GET");
}

#[tokio::test]
async fn a_draining_node_asks_the_connection_to_leave_and_cuts_it_when_idle() {
    let mut watched = watched(timeouts(10_000, 10_000)).await;
    drop(watched.conn.begin_request());

    watched.drain.send_replace(true);
    let (failure, after) = read_until_failure(&mut watched.stream).await;

    assert!(*watched.leave.borrow());
    assert_eq!(failure.kind(), io::ErrorKind::TimedOut);
    // Half the drain deadline, for one more request.
    assert!(after >= Duration::from_millis(90), "{after:?}");
    assert_eq!(watched.state.expiry(), Some(Expiry::Drain));
}

#[tokio::test]
async fn an_idle_http2_connection_is_asked_to_leave_before_being_cut() {
    let mut watched = watched(timeouts(10_000, 50)).await;
    watched.client.write_all(H2_PREFACE_FOR_TEST).await.unwrap();
    let mut preface = [0u8; 24];
    assert!(
        pingora_core::protocols::Peek::try_peek(&mut watched.stream, &mut preface)
            .await
            .unwrap()
    );
    drop(watched.conn.begin_request());

    watched.leave.changed().await.unwrap();

    assert!(*watched.leave.borrow());
    assert_eq!(watched.state.expiry(), Some(Expiry::Idle));
    // Still readable: it is up to the client to leave.
    let mut read = [0u8; 24];
    watched.stream.read_exact(&mut read).await.unwrap();
    watched.client.shutdown().await.unwrap();
    assert_eq!(watched.stream.read(&mut read).await.unwrap(), 0);
    assert_eq!(watched.state.end(), Some(WireEnd::Eof));
}

const H2_PREFACE_FOR_TEST: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
