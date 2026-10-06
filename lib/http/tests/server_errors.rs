//! How a served connection ends when the client misbehaves or goes away,
//! and when the caller cuts it.
mod server_support;

use netkit_http::body::{BodyExt, Incoming, full};
use netkit_http::server::CloseReason;
use netkit_http::{Request, Response};
use server_support::*;
use std::future::pending;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

/// A handler that reads the whole request body before answering.
fn reading_the_body() -> Arc<impl netkit_http::server::Handler> {
    Arc::new(Handle(|request: Request<Incoming>| async move {
        let _ = request.into_body().collect().await;
        Response::new(full("read"))
    }))
}

#[tokio::test]
async fn a_client_that_leaves_in_the_middle_of_a_request_is_a_client_abort() {
    let (mut client, serving) = serve_pipe(reading_the_body(), options());
    client
        .write_all(b"POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 100\r\n\r\nonly ten b")
        .await
        .unwrap();

    drop(client);
    let closed = serving.closed().await;

    assert_eq!(closed.reason, CloseReason::ClientAbort);
    assert!(closed.error.is_some());
}

#[tokio::test]
async fn a_client_that_resets_the_connection_is_a_client_abort() {
    let (entered_tx, mut entered) = mpsc::channel(1);
    let handler = Arc::new(Handle(move |_request| {
        let entered_tx = entered_tx.clone();
        async move {
            entered_tx.send(()).await.unwrap();
            pending::<Response<_>>().await
        }
    }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (accepted, _) = listener.accept().await.unwrap();
    let serving = spawn_serve(accepted, handler, options());
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        .await
        .unwrap();
    entered.recv().await.unwrap();

    // Closing with a linger of zero sends a RST instead of a FIN.
    client.set_zero_linger().unwrap();
    drop(client);
    let closed = serving.closed().await;

    assert_eq!(closed.reason, CloseReason::ClientAbort);
}

#[tokio::test]
async fn a_malformed_head_is_refused_with_400_as_a_protocol_error() {
    let (mut client, serving) = serve_pipe(hello(), options());

    client
        .write_all(b"GET / HTTP/1.1\r\nHost: test\r\nnot a header\r\n\r\n")
        .await
        .unwrap();
    let response = read_response(&mut client).await;
    let closed = serving.closed().await;

    assert!(
        response.head.starts_with("HTTP/1.1 400"),
        "{}",
        response.head
    );
    assert_eq!(closed.reason, CloseReason::ProtocolError);
    assert_eq!(closed.requests, 0);
}

#[tokio::test]
async fn a_head_over_the_limit_is_refused_with_431_as_a_protocol_error() {
    let (mut client, serving) = serve_pipe(hello(), options());
    let large = "a".repeat(options().max_header_bytes);

    client
        .write_all(format!("GET / HTTP/1.1\r\nHost: test\r\nX-Large: {large}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let response = read_response(&mut client).await;
    let closed = serving.closed().await;

    assert!(
        response.head.starts_with("HTTP/1.1 431"),
        "{}",
        response.head
    );
    assert_eq!(closed.reason, CloseReason::ProtocolError);
}

#[tokio::test]
async fn accepts_a_head_within_the_limit() {
    let (mut client, _serving) = serve_pipe(hello(), options());
    let large = "a".repeat(options().max_header_bytes / 2);

    client
        .write_all(format!("GET / HTTP/1.1\r\nHost: test\r\nX-Large: {large}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let response = read_response(&mut client).await;

    assert!(
        response.head.starts_with("HTTP/1.1 200"),
        "{}",
        response.head
    );
}

#[tokio::test]
async fn dropping_the_serving_future_closes_the_connection() {
    let (mut client, serving) = serve_pipe(hello(), options());
    get(&mut client).await;

    serving.closed.abort();

    let mut rest = Vec::new();
    assert_eq!(client.read_to_end(&mut rest).await.unwrap(), 0);
}

#[tokio::test]
async fn dropping_the_serving_future_cancels_the_requests_in_flight() {
    // The handler holds `alive` until it is dropped; the test hears of that
    // through the receiving end.
    let (entered_tx, mut entered) = mpsc::channel(1);
    let handler = Arc::new(Handle(move |_request| {
        let entered_tx = entered_tx.clone();
        let (alive, gone) = oneshot::channel::<()>();
        async move {
            entered_tx.send(gone).await.unwrap();
            let _alive = alive;
            pending::<Response<_>>().await
        }
    }));
    let (client, serving) = serve_pipe(handler, options());
    let mut sender = h2_client(client).await;
    let _response = tokio::spawn(sender.send_request(h2_get()));
    let gone = entered.recv().await.unwrap();

    serving.closed.abort();

    assert!(gone.await.is_err(), "the handler outlived the connection");
}
