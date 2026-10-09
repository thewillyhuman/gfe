use super::*;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use tokio::net::TcpStream;

/// The mock upstream on a loopback port of its own; its address.
async fn spawn_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_on(listener, Bytes::from_static(b"xxx")));
    addr
}

#[tokio::test]
async fn reads_the_body_of_an_upload_so_that_the_connection_carries_the_next_request() {
    let addr = spawn_upstream().await;
    let stream = TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);

    for _ in 0..2 {
        let upload = Request::post("/")
            .body(Full::new(Bytes::from(vec![b'u'; 100_000])))
            .unwrap();
        let response = sender.send_request(upload).await.unwrap();

        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"xxx");
    }
}
