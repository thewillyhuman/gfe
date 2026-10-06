use super::*;
use crate::edge::test_support::{CapturedLogs, acceptor};
use gfe_config::{ListenProtocol, ListenerId, TimeoutsConfig};
use tokio::io::AsyncWriteExt;

#[test]
fn a_connection_that_ended_in_order_is_closed() {
    assert_eq!(close_reason(CloseReason::Closed), "closed");
}

#[test]
fn a_connection_that_left_when_drained_is_drain() {
    assert_eq!(close_reason(CloseReason::Drain), "drain");
}

#[test]
fn a_connection_idle_for_too_long_timed_out() {
    assert_eq!(close_reason(CloseReason::IdleTimeout), "idle_timeout");
}

#[test]
fn a_connection_that_never_sent_a_request_head_timed_out() {
    assert_eq!(close_reason(CloseReason::HeaderTimeout), "header_timeout");
}

#[test]
fn a_client_that_reset_or_left_in_the_middle_of_a_message_aborted() {
    assert_eq!(close_reason(CloseReason::ClientAbort), "client_abort");
}

#[test]
fn a_client_that_stopped_answering_is_unresponsive() {
    assert_eq!(
        close_reason(CloseReason::ClientUnresponsive),
        "client_unresponsive"
    );
}

#[test]
fn a_client_that_sent_what_is_not_http_is_a_protocol_error() {
    assert_eq!(close_reason(CloseReason::ProtocolError), "protocol_error");
}

#[test]
fn a_connection_that_failed_otherwise_is_an_error() {
    assert_eq!(close_reason(CloseReason::Error), "error");
}

fn listener() -> Listener {
    Listener {
        id: ListenerId("web".into()),
        address: "127.0.0.1".parse().unwrap(),
        port: 80,
        protocol: ListenProtocol::Http,
    }
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn shared() -> Arc<Shared> {
    crate::edge::test_support::shared(TimeoutsConfig::default(), acceptor(&[]).1)
}

fn open(shared: &Arc<Shared>) -> ConnRecord {
    ConnRecord::open(Arc::clone(shared), &listener(), addr(80), addr(40000))
}

fn closed(reason: CloseReason, requests: u64) -> Closed {
    Closed {
        reason,
        requests,
        error: None,
    }
}

#[test]
fn counts_a_connection_while_it_is_open_and_its_end_once() {
    let shared = shared();
    let record = open(&shared);
    let open = shared.metrics().encode();

    drop(record);

    let closed = shared.metrics().encode();
    assert!(open.contains("gfe_connections_active 1"), "{open}");
    assert!(
        open.contains(r#"gfe_connections_accepted_total{listener="web"} 1"#),
        "{open}"
    );
    assert!(closed.contains("gfe_connections_active 0"), "{closed}");
    assert!(
        closed.contains(r#"gfe_listener_connections_active{listener="web"} 0"#),
        "{closed}"
    );
    assert!(
        closed.contains(r#"gfe_connection_duration_seconds_count{listener="web"} 1"#),
        "{closed}"
    );
}

#[test]
fn a_connection_dropped_before_it_ended_is_shutdown() {
    let shared = shared();

    // What cutting a connection at the drain deadline does to its record.
    drop(open(&shared));

    let exposed = shared.metrics().encode();
    assert!(
        exposed.contains(r#"gfe_connections_closed_total{listener="web",reason="shutdown"} 1"#),
        "{exposed}"
    );
}

#[test]
fn a_connection_whose_task_panicked_is_an_error() {
    let shared = shared();
    let record = open(&shared);

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _record = record;
        panic!("the code serving the connection failed");
    }));

    assert!(panicked.is_err());
    let exposed = shared.metrics().encode();
    assert!(
        exposed.contains(r#"gfe_connections_closed_total{listener="web",reason="error"} 1"#),
        "{exposed}"
    );
}

#[test]
fn counts_a_connection_under_the_reason_it_ended_with() {
    let shared = shared();
    let mut record = open(&shared);

    record.closed(&closed(CloseReason::IdleTimeout, 2));
    drop(record);

    let exposed = shared.metrics().encode();
    assert!(
        exposed.contains(r#"gfe_connections_closed_total{listener="web",reason="idle_timeout"} 1"#),
        "{exposed}"
    );
}

#[tokio::test]
async fn logs_the_requests_and_the_error_a_connection_ended_with() {
    let (logs, _capturing) = CapturedLogs::start();
    let shared = shared();
    let mut record = open(&shared);

    record.closed(&Closed {
        reason: CloseReason::Error,
        requests: 3,
        error: Some("connection error: something odd".into()),
    });
    drop(record);
    let event = logs.connection_event().await;

    assert_eq!(event["requests"], 3);
    assert_eq!(event["reason"], "error");
    assert_eq!(event["error"], "connection error: something odd");
    assert_eq!(event["listener"], "web");
    assert_eq!(event["proto"], "http");
    assert_eq!(event["client"], "127.0.0.1");
    assert_eq!(event["client_port"], 40000);
}

#[test]
fn a_timed_out_handshake_is_counted_as_rejected() {
    let shared = shared();
    let mut record = open(&shared);

    record.tls_timed_out();
    drop(record);

    let exposed = shared.metrics().encode();
    assert!(
        exposed.contains(r#"gfe_connections_rejected_total{reason="handshake_timeout"} 1"#),
        "{exposed}"
    );
    assert!(
        exposed.contains(r#"reason="tls_handshake_timeout"} 1"#),
        "{exposed}"
    );
}

#[tokio::test]
async fn counts_a_failed_handshake_by_its_reason() {
    let (acceptor, _) = acceptor(&[]);
    let (mut client, server) = tokio::io::duplex(4096);
    client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let failure = acceptor.accept(server).await.unwrap_err();
    let shared = shared();
    let mut record = open(&shared);

    record.tls_failed(&failure);
    drop(record);

    let exposed = shared.metrics().encode();
    assert!(
        exposed.contains(r#"gfe_tls_handshake_failures_total{reason="invalid_message"} 1"#),
        "{exposed}"
    );
    assert!(
        exposed.contains(r#"gfe_tls_handshakes_total{result="failed"} 1"#),
        "{exposed}"
    );
    assert!(
        exposed.contains(r#"reason="tls_handshake_failed"} 1"#),
        "{exposed}"
    );
}

#[tokio::test]
async fn counts_the_bytes_of_its_stream_under_its_listener() {
    use tokio::io::AsyncReadExt;
    let shared = shared();
    let mut record = open(&shared);
    let (mut client, server) = tokio::io::duplex(4096);
    let mut server = record.meter(server);

    client.write_all(b"ping").await.unwrap();
    let mut received = [0u8; 4];
    server.read_exact(&mut received).await.unwrap();
    server.write_all(b"pong!").await.unwrap();
    drop(record);

    let exposed = shared.metrics().encode();
    assert!(
        exposed.contains(r#"gfe_bytes_in_total{listener="web"} 4"#),
        "{exposed}"
    );
    assert!(
        exposed.contains(r#"gfe_bytes_out_total{listener="web"} 5"#),
        "{exposed}"
    );
}

/// A kernel view that knows every connection waited 5 ms, and remembers
/// which addresses it was asked about.
#[derive(Default)]
struct WaitedFiveMillis(std::sync::Mutex<Vec<(SocketAddr, SocketAddr)>>);

impl crate::edge::AcceptQueue for WaitedFiveMillis {
    fn waited(&self, local: SocketAddr, peer: SocketAddr) -> Option<Duration> {
        self.0.lock().unwrap().push((local, peer));
        Some(Duration::from_millis(5))
    }
}

#[tokio::test]
async fn reports_how_long_the_connection_waited_to_be_accepted() {
    let (logs, _capturing) = CapturedLogs::start();
    let kernel = Arc::new(WaitedFiveMillis::default());
    let shared = Arc::new(
        Shared::new(
            Arc::new(crate::metrics::GfeMetrics::new()),
            gfe_config::LimitsConfig::default(),
            TimeoutsConfig::default(),
        )
        .with_accept_queue(Arc::clone(&kernel) as _),
    );
    let mapped = |port| SocketAddr::new("::ffff:127.0.0.1".parse().unwrap(), port);

    drop(ConnRecord::open(
        Arc::clone(&shared),
        &listener(),
        mapped(80),
        mapped(40000),
    ));
    let event = logs.connection_event().await;

    assert_eq!(*kernel.0.lock().unwrap(), vec![(addr(80), addr(40000))]);
    assert_eq!(event["accept_wait_ms"], 5.0);
    let exposed = shared.metrics().encode();
    assert!(
        exposed.contains(r#"gfe_accept_queue_wait_seconds_count{listener="web"} 1"#),
        "{exposed}"
    );
}

#[test]
fn an_ipv4_client_of_a_dual_stack_socket_is_logged_as_ipv4() {
    let mapped: SocketAddr = "[::ffff:192.0.2.1]:40000".parse().unwrap();

    let record = ConnRecord::open(shared(), &listener(), addr(80), mapped);

    assert_eq!(record.client, "192.0.2.1:40000".parse().unwrap());
}
