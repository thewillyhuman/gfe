use super::*;
use crate::listener::test_support::{TestCert, acceptor, connector, tcp_pair};
use rustls::pki_types::ServerName;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn metered<S>(inner: S) -> (Metered<S>, Counter, Counter) {
    let (read_total, written_total) = (Counter::default(), Counter::default());
    let wire = Metered::new(
        inner,
        Arc::new(StreamState::default()),
        read_total.clone(),
        written_total.clone(),
    );
    (wire, read_total, written_total)
}

/// A socket whose every read and write fails with `kind`.
struct Failing(io::ErrorKind);

impl AsyncRead for Failing {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(self.0.into()))
    }
}

impl AsyncWrite for Failing {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(self.0.into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn counts_the_bytes_on_the_wire_in_both_directions() {
    let (client, server) = tokio::io::duplex(1024);
    let (mut wire, read_total, written_total) = metered(server);
    let mut client = client;

    client.write_all(b"hello").await.unwrap();
    let mut received = [0u8; 5];
    wire.read_exact(&mut received).await.unwrap();
    wire.write_all(b"hi").await.unwrap();

    assert_eq!(wire.state().bytes_in(), 5);
    assert_eq!(wire.state().bytes_out(), 2);
    assert_eq!(read_total.get(), 5);
    assert_eq!(written_total.get(), 2);
}

#[tokio::test]
async fn remembers_that_the_client_closed_its_side() {
    let (client, server) = tokio::io::duplex(1024);
    let (mut wire, _, _) = metered(server);
    drop(client);

    let read = wire.read(&mut [0u8; 16]).await.unwrap();

    assert_eq!(read, 0);
    assert_eq!(wire.state().end(), Some(WireEnd::Eof));
}

#[tokio::test]
async fn a_read_with_no_room_is_not_taken_for_the_end() {
    let (mut client, server) = tokio::io::duplex(1024);
    let (mut wire, _, _) = metered(server);
    client.write_all(b"waiting").await.unwrap();

    let read = wire.read(&mut []).await.unwrap();

    assert_eq!(read, 0);
    assert_eq!(wire.state().end(), None);
}

#[tokio::test]
async fn remembers_a_reset_under_a_read_and_its_error() {
    let (mut wire, _, _) = metered(Failing(io::ErrorKind::ConnectionReset));

    let _ = wire.read(&mut [0u8; 16]).await;

    assert_eq!(wire.state().end(), Some(WireEnd::Reset));
    assert!(wire.state().error().is_some());
}

#[tokio::test]
async fn remembers_a_broken_pipe_under_a_write() {
    let (mut wire, _, _) = metered(Failing(io::ErrorKind::BrokenPipe));

    let _ = wire.write(b"late").await;

    assert_eq!(wire.state().end(), Some(WireEnd::Reset));
}

#[tokio::test]
async fn remembers_a_peer_given_up_by_tcp_keepalive() {
    let (mut wire, _, _) = metered(Failing(io::ErrorKind::TimedOut));

    let _ = wire.read(&mut [0u8; 16]).await;

    assert_eq!(wire.state().end(), Some(WireEnd::TimedOut));
}

#[tokio::test]
async fn the_first_sign_of_the_end_is_the_one_remembered() {
    let (client, server) = tokio::io::duplex(1024);
    let (mut wire, _, _) = metered(server);
    drop(client);
    let _ = wire.read(&mut [0u8; 16]).await;

    let _ = wire.write(b"late").await;

    assert_eq!(wire.state().end(), Some(WireEnd::Eof));
}

#[test]
fn maps_the_protocols_the_node_offers_by_alpn() {
    assert_eq!(alpn(Some(b"h2")), Some(ALPN::H2));
    assert_eq!(alpn(Some(b"http/1.1")), Some(ALPN::H1));
    assert_eq!(alpn(Some(b"spdy/3")), None);
    assert_eq!(alpn(None), None);
}

/// A plain [`ClientStream`] over the server end of a loopback connection,
/// and the client end.
async fn plain_stream() -> (ClientStream, tokio::net::TcpStream) {
    let (client, server) = tcp_pair().await;
    let (wire, _, _) = metered(L4Stream::from(server));
    (ClientStream::plain(wire), client)
}

#[tokio::test]
async fn reads_and_writes_a_plain_connection_and_counts_it() {
    let (mut stream, mut client) = plain_stream().await;

    client.write_all(b"ping").await.unwrap();
    let mut received = [0u8; 4];
    stream.read_exact(&mut received).await.unwrap();
    stream.write_all(b"pong").await.unwrap();
    stream.flush().await.unwrap();
    let mut answered = [0u8; 4];
    client.read_exact(&mut answered).await.unwrap();

    assert_eq!(&received, b"ping");
    assert_eq!(&answered, b"pong");
    assert_eq!(stream.state.bytes_in(), 4);
    assert_eq!(stream.state.bytes_out(), 4);
}

#[tokio::test]
async fn a_cut_ends_a_waiting_read_with_timed_out() {
    let (mut stream, _client) = plain_stream().await;
    let state = Arc::clone(&stream.state);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        state.cut(Expiry::Header);
    });

    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut [0u8; 16]))
        .await
        .expect("the cut should end the read");

    assert_eq!(read.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(stream.state.expiry(), Some(Expiry::Header));
    // The client did nothing: the end is the edge's, not the wire's.
    assert_eq!(stream.state.end(), None);
}

#[tokio::test]
async fn data_received_before_a_cut_is_still_read() {
    let (mut stream, mut client) = plain_stream().await;
    client.write_all(b"late").await.unwrap();
    // Let the bytes reach the server's socket.
    tokio::time::sleep(Duration::from_millis(20)).await;
    stream.state.cut(Expiry::Idle);

    let mut received = [0u8; 4];
    stream.read_exact(&mut received).await.unwrap();
    let next = stream.read(&mut [0u8; 4]).await;

    assert_eq!(&received, b"late");
    assert_eq!(next.unwrap_err().kind(), io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn a_cut_does_not_stop_a_response_being_written() {
    let (mut stream, mut client) = plain_stream().await;
    stream.state.cut(Expiry::Drain);

    stream.write_all(b"bye").await.unwrap();
    stream.flush().await.unwrap();
    let mut answered = [0u8; 3];
    client.read_exact(&mut answered).await.unwrap();

    assert_eq!(&answered, b"bye");
}

#[tokio::test]
async fn peeking_finds_an_http2_client_and_its_bytes_are_counted_once() {
    let (mut stream, mut client) = plain_stream().await;
    client.write_all(H2_PREFACE).await.unwrap();

    let mut peeked = [0u8; 24];
    assert!(stream.try_peek(&mut peeked).await.unwrap());
    let mut read = [0u8; 24];
    stream.read_exact(&mut read).await.unwrap();

    assert!(stream.state.is_h2());
    assert_eq!(&read[..], H2_PREFACE);
    assert_eq!(stream.state.bytes_in(), 24);
}

#[tokio::test]
async fn peeking_at_an_http1_request_does_not_take_it_for_http2() {
    let (mut stream, mut client) = plain_stream().await;
    client
        .write_all(b"GET / HTTP/1.1\r\nhost: a.example.org\r\n\r\n")
        .await
        .unwrap();

    let mut peeked = [0u8; 24];
    assert!(stream.try_peek(&mut peeked).await.unwrap());

    assert!(!stream.state.is_h2());
}

#[tokio::test]
async fn a_cut_ends_a_peek_that_waits() {
    let (mut stream, _client) = plain_stream().await;
    stream.state.cut(Expiry::Header);

    let peeked = stream.try_peek(&mut [0u8; 24]).await;

    assert_eq!(peeked.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(stream.state.end(), None);
}

#[tokio::test]
async fn a_client_leaving_during_a_peek_has_closed_its_side() {
    let (mut stream, client) = plain_stream().await;
    drop(client);

    let mut peeked = [0u8; 24];
    assert!(stream.try_peek(&mut peeked).await.unwrap());

    assert!(!stream.state.is_h2());
    assert_eq!(stream.state.end(), Some(WireEnd::Eof));
}

#[tokio::test]
async fn peeking_at_a_request_shorter_than_the_preface_does_not_wait_for_more() {
    let (mut stream, mut client) = plain_stream().await;
    let request = b"GET / HTTP/1.0\r\n\r\n";
    client.write_all(request).await.unwrap();

    let mut peeked = [0u8; 24];
    let peek = tokio::time::timeout(Duration::from_secs(5), stream.try_peek(&mut peeked)).await;
    let mut read = [0u8; 18];
    stream.read_exact(&mut read).await.unwrap();

    assert!(peek.expect("the peek should not wait").unwrap());
    assert!(!stream.state.is_h2());
    assert_eq!(&read, request);
    assert_eq!(stream.state.bytes_in(), request.len() as u64);
}

#[tokio::test]
async fn a_preface_sent_in_pieces_is_still_found() {
    let (mut stream, mut client) = plain_stream().await;
    tokio::spawn(async move {
        client.write_all(&H2_PREFACE[..10]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        client.write_all(&H2_PREFACE[10..]).await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });

    let mut peeked = [0u8; 24];
    assert!(stream.try_peek(&mut peeked).await.unwrap());
    let mut read = [0u8; 24];
    stream.read_exact(&mut read).await.unwrap();

    assert!(stream.state.is_h2());
    assert_eq!(&read[..], H2_PREFACE);
}

#[tokio::test]
async fn a_plain_connection_has_no_tls_digest_nor_alpn() {
    let (stream, _client) = plain_stream().await;

    assert!(stream.get_ssl_digest().is_none());
    assert!(stream.selected_alpn_proto().is_none());
}

/// A TLS [`ClientStream`] whose client offered `alpn`, and the client's end.
async fn tls_stream(
    alpn: &[&[u8]],
) -> (
    ClientStream,
    tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) {
    let cert = TestCert::new("a.example.org");
    let (acceptor, _) = acceptor(&[&cert]);
    let (client, server) = tcp_pair().await;
    let (wire, _, _) = metered(L4Stream::from(server));
    let name = ServerName::try_from("a.example.org").unwrap();
    let (client, server) = tokio::join!(
        connector(&[&cert], alpn).connect(name, client),
        acceptor.accept(wire)
    );
    let (server, info) = server.unwrap();
    (ClientStream::tls(server, &info), client.unwrap())
}

#[tokio::test]
async fn a_tls_connection_reports_http2_chosen_by_alpn_and_a_tls_digest() {
    let (stream, _client) = tls_stream(&[b"h2", b"http/1.1"]).await;

    assert_eq!(stream.selected_alpn_proto(), Some(ALPN::H2));
    assert!(stream.state.is_h2());
    let digest = stream.get_ssl_digest().unwrap();
    assert_eq!(digest.version, "TLSv1.3");
    assert!(digest.cipher.starts_with("TLS13_"), "{}", digest.cipher);
}

#[tokio::test]
async fn a_tls_connection_reports_http1_chosen_by_alpn() {
    let (stream, _client) = tls_stream(&[b"http/1.1"]).await;

    assert_eq!(stream.selected_alpn_proto(), Some(ALPN::H1));
    assert!(!stream.state.is_h2());
}

#[tokio::test]
async fn counts_tls_bytes_on_the_wire() {
    let (mut stream, mut client) = tls_stream(&[b"http/1.1"]).await;
    let handshake_in = stream.state.bytes_in();

    client.write_all(b"ping").await.unwrap();
    let mut received = [0u8; 4];
    stream.read_exact(&mut received).await.unwrap();

    assert!(handshake_in > 0);
    // A record carries more than its payload.
    assert!(stream.state.bytes_in() > handshake_in + 4);
}

#[tokio::test]
async fn a_tls_connection_given_up_tells_the_client_it_is_closing() {
    let (stream, mut client) = tls_stream(&[b"http/1.1"]).await;

    drop(stream);

    // rustls reports an end that no `close_notify` announced as an error.
    let mut rest = Vec::new();
    let ended = client.read_to_end(&mut rest).await;
    assert!(ended.is_ok(), "closed without close_notify: {ended:?}");
}

#[tokio::test]
async fn a_tls_connection_shut_down_then_dropped_still_ends_in_order() {
    let (mut stream, mut client) = tls_stream(&[b"http/1.1"]).await;

    Shutdown::shutdown(&mut stream).await;
    drop(stream);

    let mut rest = Vec::new();
    let ended = client.read_to_end(&mut rest).await;
    assert!(ended.is_ok(), "closed without close_notify: {ended:?}");
    assert!(rest.is_empty());
}

#[tokio::test]
async fn a_plain_connection_given_up_is_simply_closed() {
    let (stream, mut client) = plain_stream().await;

    drop(stream);

    let mut rest = Vec::new();
    assert_eq!(client.read_to_end(&mut rest).await.unwrap(), 0);
}
