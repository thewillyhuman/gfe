use super::*;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The process has one log, started once for all the tests.
fn log() -> Arc<Log> {
    static LOG: OnceLock<Arc<Log>> = OnceLock::new();
    LOG.get_or_init(|| Arc::new(Log::start(None, &crate::LOG).unwrap()))
        .clone()
}

/// An empty directory of its own for `test`.
fn scratch(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gfe-node-ops-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A front end with one listener on a loopback port, and no route.
fn frontend(test: &str, metrics: &Arc<GfeMetrics>) -> Arc<Frontend> {
    let dir = scratch(test);
    std::fs::write(
        dir.join("gfe-dynamic.json"),
        r#"{"listeners":[{"id":"http","address":"127.0.0.1","port":0,"protocol":"http"}]}"#,
    )
    .unwrap();
    let bootstrap = dir.join("gfe.toml");
    std::fs::write(
        &bootstrap,
        format!(
            "[node]\nid = \"t\"\n\n[control_plane]\nconfig_file = \"{}\"\n\n\
             [health_check_defaults]\n",
            dir.join("gfe-dynamic.json").display()
        ),
    )
    .unwrap();
    let node = gfe_config::load_node_config(&bootstrap).unwrap();
    Arc::new(Frontend::start(&node, Arc::clone(metrics), Vec::new()).unwrap())
}

/// An ops endpoint on a loopback port: its address, what it serves, and
/// what tells it another process has taken its socket over (it stops
/// serving when that is dropped).
async fn ops_server() -> (SocketAddr, Arc<Ops>, watch::Sender<bool>) {
    let ops = Arc::new(Ops::new(Arc::new(GfeMetrics::new()), log()));
    let socket = Arc::new(listen("127.0.0.1:0".parse().unwrap(), None).await.unwrap());
    let addr = socket.local_addr().unwrap();
    let (stop, stopped) = watch::channel(false);
    tokio::spawn(serve(socket, Arc::clone(&ops), stopped));
    (addr, ops, stop)
}

/// An ops endpoint of a node that serves; the same as [`ops_server`].
async fn serving_ops_server(test: &str) -> (SocketAddr, Arc<Ops>, watch::Sender<bool>) {
    let (addr, ops, stop) = ops_server().await;
    ops.serving(frontend(test, &ops.metrics));
    (addr, ops, stop)
}

/// What the server at the other end of `stream` sends until it closes
/// the connection, or `None` if it is still open after `wait`.
async fn read_until_closed(stream: &mut TcpStream, wait: Duration) -> Option<String> {
    let mut received = Vec::new();
    match tokio::time::timeout(wait, stream.read_to_end(&mut received)).await {
        Ok(_) => Some(String::from_utf8_lossy(&received).to_string()),
        Err(_) => None,
    }
}

/// The answer of the ops endpoint at `addr` to `method target`.
async fn request(addr: SocketAddr, method: &str, target: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!("{method} {target} HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    read_until_closed(&mut stream, Duration::from_secs(5))
        .await
        .expect("the server closes the connection")
}

/// The answer of the ops endpoint at `addr` to `GET target`.
async fn get(addr: SocketAddr, target: &str) -> String {
    request(addr, "GET", target).await
}

const HANDSHAKE_TYPE: &str = "# TYPE gfe_tls_handshake_duration_seconds histogram";
const HANDSHAKE_BUCKET: &str = "gfe_tls_handshake_duration_seconds_bucket{le=\"+Inf\"}";

#[tokio::test]
async fn healthz_answers_while_the_process_runs() {
    let (addr, _ops, _stop) = ops_server().await;

    let answer = get(addr, "/healthz").await;

    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.ends_with("ok\n"), "{answer}");
}

#[tokio::test]
async fn readyz_fails_until_the_node_serves() {
    let (addr, _ops, _stop) = ops_server().await;

    let answer = get(addr, "/readyz").await;

    assert!(answer.starts_with("HTTP/1.1 503"), "{answer}");
}

#[tokio::test]
async fn readyz_answers_once_the_node_serves() {
    let (addr, _ops, _stop) = serving_ops_server("ready").await;

    let answer = get(addr, "/readyz").await;

    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.ends_with("ready\n"), "{answer}");
}

#[tokio::test]
async fn readyz_fails_while_the_node_drains() {
    let (addr, ops, _stop) = serving_ops_server("draining").await;

    ops.frontend.get().unwrap().drain().await;
    let answer = get(addr, "/readyz").await;

    assert!(answer.starts_with("HTTP/1.1 503"), "{answer}");
}

#[tokio::test]
async fn answers_any_method_as_it_answers_get() {
    let (addr, _ops, _stop) = ops_server().await;

    let answer = request(addr, "POST", "/healthz").await;

    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
}

#[tokio::test]
async fn answers_404_to_any_other_path() {
    let (addr, _ops, _stop) = ops_server().await;

    let answer = get(addr, "/status").await;

    assert!(answer.starts_with("HTTP/1.1 404"), "{answer}");
}

#[tokio::test]
async fn metrics_declare_their_histograms() {
    let (addr, _ops, _stop) = ops_server().await;

    let answer = get(addr, "/metrics").await;

    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(
        answer.contains("content-type: application/openmetrics-text; version=1.0.0"),
        "{answer}"
    );
    assert!(answer.contains(HANDSHAKE_TYPE), "{answer}");
    assert!(answer.contains(HANDSHAKE_BUCKET), "{answer}");
}

#[tokio::test]
async fn metrics_leave_histograms_untyped_when_asked() {
    let (addr, _ops, _stop) = ops_server().await;

    let answer = get(addr, "/metrics?histograms=untyped").await;

    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(!answer.contains(HANDSHAKE_TYPE), "{answer}");
    assert!(answer.contains(HANDSHAKE_BUCKET), "{answer}");
}

#[tokio::test]
async fn metrics_refuse_an_unknown_way_to_expose_histograms() {
    let (addr, _ops, _stop) = ops_server().await;

    let answer = get(addr, "/metrics?histograms=native").await;

    assert!(answer.starts_with("HTTP/1.1 400"), "{answer}");
}

#[tokio::test]
async fn metrics_ignore_parameters_they_do_not_know() {
    let (addr, _ops, _stop) = ops_server().await;

    let answer = get(addr, "/metrics?collect=all").await;

    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.contains(HANDSHAKE_TYPE), "{answer}");
}

#[tokio::test]
async fn metrics_tell_the_build() {
    let (addr, _ops, _stop) = ops_server().await;

    let answer = get(addr, "/metrics").await;

    let build = format!(
        "gfe_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );
    assert!(answer.contains(&build), "{answer}");
}

#[tokio::test]
async fn metrics_sample_the_runtime_and_the_log_when_scraped() {
    let (addr, _ops, _stop) = ops_server().await;

    let answer = get(addr, "/metrics").await;

    assert!(
        answer.lines().any(|line| line.starts_with("gfe_runtime_workers ")
            && line != "gfe_runtime_workers 0"),
        "{answer}"
    );
    assert!(
        answer.contains(r#"gfe_log_lost_lines{destination="stdout"} 0"#),
        "{answer}"
    );
}

/// A prober whose connection the outgoing node accepted just before
/// the handover asks it, not the successor, and the outgoing node is
/// draining by then.
#[tokio::test]
async fn answers_for_the_successor_on_a_connection_accepted_before_the_handover() {
    let (addr, ops, stop) = serving_ops_server("handed-over").await;
    let mut prober = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    stop.send(true).unwrap();
    ops.frontend.get().unwrap().drain().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    prober
        .write_all(b"GET /readyz HTTP/1.1\r\nhost: t\r\n\r\n")
        .await
        .unwrap();
    let answer = read_until_closed(&mut prober, Duration::from_secs(2)).await;

    let answer = answer.unwrap_or_default().to_ascii_lowercase();
    assert!(answer.starts_with("http/1.1 200"), "{answer}");
    assert!(answer.contains("connection: close"), "{answer}");
}

/// A client that keeps its connection asks the process that serves now
/// with its next request.
#[tokio::test]
async fn closes_a_kept_connection_once_the_socket_is_handed_over() {
    let (addr, _ops, stop) = ops_server().await;
    let mut kept = TcpStream::connect(addr).await.unwrap();
    kept.write_all(b"GET /healthz HTTP/1.1\r\nhost: t\r\n\r\n")
        .await
        .unwrap();
    let mut answer = [0u8; 17];
    kept.read_exact(&mut answer).await.unwrap();
    assert_eq!(&answer, b"HTTP/1.1 200 OK\r\n");

    stop.send(true).unwrap();
    let closed = read_until_closed(&mut kept, Duration::from_secs(2)).await;

    assert!(closed.is_some(), "the kept connection is still open");
}

#[tokio::test]
async fn stops_accepting_once_the_socket_is_handed_over() {
    let ops = Arc::new(Ops::new(Arc::new(GfeMetrics::new()), log()));
    // Kept open, as the node keeps it to hand it over again.
    let socket = Arc::new(listen("127.0.0.1:0".parse().unwrap(), None).await.unwrap());
    let addr = socket.local_addr().unwrap();
    let (stop, stopped) = watch::channel(false);
    let serving = tokio::spawn(serve(Arc::clone(&socket), ops, stopped));

    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), serving)
        .await
        .expect("the endpoint stops serving")
        .unwrap();
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    let answer = read_until_closed(&mut stream, Duration::from_millis(500)).await;

    assert_eq!(
        answer, None,
        "the endpoint still answers after the handover"
    );
}

#[tokio::test]
async fn closes_a_connection_that_never_sends_a_request() {
    let (addr, _ops, _stop) = ops_server().await;
    let mut silent = TcpStream::connect(addr).await.unwrap();

    let closed = read_until_closed(&mut silent, HEADER_READ_TIMEOUT * 2).await;

    assert_eq!(closed.as_deref(), Some(""));
}

#[tokio::test]
async fn closes_a_kept_connection_that_sends_no_further_request() {
    let (addr, _ops, _stop) = ops_server().await;
    let mut kept = TcpStream::connect(addr).await.unwrap();
    kept.write_all(b"GET /healthz HTTP/1.1\r\nhost: t\r\n\r\n")
        .await
        .unwrap();

    let closed = read_until_closed(&mut kept, HEADER_READ_TIMEOUT * 2).await;

    assert!(
        closed
            .as_deref()
            .is_some_and(|c| c.starts_with("HTTP/1.1 200")),
        "{closed:?}"
    );
}

#[tokio::test]
async fn serves_requests_one_after_the_other_on_a_kept_connection() {
    let (addr, _ops, _stop) = ops_server().await;
    let mut kept = TcpStream::connect(addr).await.unwrap();

    kept.write_all(b"GET /healthz HTTP/1.1\r\nhost: t\r\n\r\n")
        .await
        .unwrap();
    let mut first = Vec::new();
    let mut chunk = [0u8; 256];
    while !first.ends_with(b"\r\n\r\nok\n") {
        let read = kept.read(&mut chunk).await.unwrap();
        assert_ne!(
            read,
            0,
            "closed after {:?}",
            String::from_utf8_lossy(&first)
        );
        first.extend_from_slice(&chunk[..read]);
    }
    kept.write_all(b"GET /healthz HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    let second = read_until_closed(&mut kept, Duration::from_secs(2))
        .await
        .unwrap_or_default();

    assert!(second.starts_with("HTTP/1.1 200"), "{second}");
}

#[tokio::test]
async fn closes_a_connection_over_the_cap_at_once() {
    let (addr, _ops, _stop) = ops_server().await;
    let mut under_the_cap = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        under_the_cap.push(TcpStream::connect(addr).await.unwrap());
    }
    let mut over_the_cap = TcpStream::connect(addr).await.unwrap();

    over_the_cap
        .write_all(b"GET /healthz HTTP/1.1\r\nhost: t\r\n\r\n")
        .await
        .unwrap();
    let answer = read_until_closed(&mut over_the_cap, Duration::from_secs(2)).await;

    assert_eq!(answer.as_deref(), Some(""));
}

#[tokio::test]
async fn serves_connections_under_the_cap() {
    let (addr, _ops, _stop) = ops_server().await;
    let mut others = Vec::new();
    for _ in 0..MAX_CONNECTIONS - 1 {
        others.push(TcpStream::connect(addr).await.unwrap());
    }
    let mut last = TcpStream::connect(addr).await.unwrap();

    last.write_all(b"GET /healthz HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    let answer = read_until_closed(&mut last, Duration::from_secs(2)).await;

    assert!(
        answer
            .as_deref()
            .is_some_and(|a| a.starts_with("HTTP/1.1 200")),
        "{answer:?}"
    );
}

#[tokio::test]
async fn listens_on_an_inherited_socket_configured_on_its_address() {
    let inherited = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let configured = inherited.local_addr().unwrap();

    let socket = listen(configured, Some((configured, inherited)))
        .await
        .unwrap();

    assert_eq!(socket.local_addr().unwrap(), configured);
}

#[tokio::test]
async fn binds_its_own_address_rather_than_an_inherited_socket_configured_elsewhere() {
    let inherited = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let elsewhere = inherited.local_addr().unwrap();

    let socket = listen("127.0.0.1:0".parse().unwrap(), Some((elsewhere, inherited)))
        .await
        .unwrap();

    assert_ne!(socket.local_addr().unwrap(), elsewhere);
}
