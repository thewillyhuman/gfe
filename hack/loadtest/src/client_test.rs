use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A server that answers one request per connection and says so.
async fn spawn_server_closing_after_each_response() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await;
                let response =
                    b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok";
                let _ = stream.write_all(response).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn keepalive_client_reconnects_when_told_to_without_counting_an_error() {
    let server = spawn_server_closing_after_each_response().await;
    let target = Arc::new(parse_target(&format!("http://{server}/")).unwrap());
    let deadline = Instant::now() + Duration::from_millis(200);

    let (answered, errors) = worker_keepalive(target, None, deadline).await;

    assert_eq!(errors, 0);
    assert!(answered.len() > 1, "{} requests answered", answered.len());
}

#[test]
fn the_mode_names_a_full_handshake_per_request_only_over_tls() {
    let over = |url: &str, reconnect: bool, resume: bool| Scenario {
        target: Arc::new(parse_target(url).unwrap()),
        connections: 1,
        duration: Duration::ZERO,
        reconnect,
        resume,
        label: String::new(),
    };

    assert_eq!(over("http://h/", false, true).mode(), "keepalive");
    assert_eq!(over("http://h/", true, false).mode(), "reconnect");
    assert_eq!(over("https://h/", true, true).mode(), "reconnect");
    assert_eq!(over("https://h/", true, false).mode(), "reconnect+full-tls");
}
