use super::*;
use tokio::net::TcpListener;

/// The server's end of a loopback connection, and the client's.
async fn connection() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (server, client)
}

#[tokio::test]
async fn has_the_kernel_probe_a_silent_peer_as_asked() {
    let (stream, _client) = connection().await;

    keep_alive(&stream, Duration::from_secs(30), Duration::from_secs(5), 3).unwrap();

    let socket = SockRef::from(&stream);
    assert!(socket.keepalive().unwrap());
    assert_eq!(
        socket.tcp_keepalive_time().unwrap(),
        Duration::from_secs(30)
    );
    assert_eq!(
        socket.tcp_keepalive_interval().unwrap(),
        Duration::from_secs(5)
    );
    assert_eq!(socket.tcp_keepalive_retries().unwrap(), 3);
}

#[tokio::test]
async fn refuses_an_idle_time_shorter_than_a_second() {
    let (stream, _client) = connection().await;

    let set = keep_alive(
        &stream,
        Duration::from_millis(500),
        Duration::from_secs(5),
        3,
    );

    assert_eq!(set.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    assert!(!SockRef::from(&stream).keepalive().unwrap());
}

#[tokio::test]
async fn refuses_an_interval_shorter_than_a_second() {
    let (stream, _client) = connection().await;

    let set = keep_alive(&stream, Duration::from_secs(30), Duration::ZERO, 3);

    assert_eq!(set.unwrap_err().kind(), io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn refuses_to_give_a_peer_up_without_a_probe() {
    let (stream, _client) = connection().await;

    let set = keep_alive(&stream, Duration::from_secs(30), Duration::from_secs(5), 0);

    assert_eq!(set.unwrap_err().kind(), io::ErrorKind::InvalidInput);
}
