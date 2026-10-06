//! Draining a served connection: the client is asked to leave in a way
//! that loses no request. Time is paused: it jumps ahead whenever nothing
//! else is left to do.
mod server_support;

use netkit_http::Response;
use netkit_http::body::full;
use netkit_http::server::{self, CloseReason, Handler};
use server_support::raw_h2::{self, RawH2};
use server_support::*;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

/// A handler that tells `entered` when a request reaches it, and answers it
/// once `release` lets it.
fn held_until_released() -> (Arc<impl Handler>, mpsc::Receiver<()>, mpsc::Sender<()>) {
    let (entered_tx, entered) = mpsc::channel(8);
    let (release, release_rx) = mpsc::channel::<()>(8);
    let release_rx = Arc::new(tokio::sync::Mutex::new(release_rx));
    let handler = Arc::new(Handle(move |_request| {
        let entered_tx = entered_tx.clone();
        let release_rx = release_rx.clone();
        async move {
            entered_tx.send(()).await.unwrap();
            release_rx.lock().await.recv().await;
            Response::new(full("released"))
        }
    }));
    (handler, entered, release)
}

#[tokio::test(start_paused = true)]
async fn answers_an_http1_request_in_flight_with_connection_close() {
    let (handler, mut entered, release) = held_until_released();
    let (mut client, serving) = serve_pipe(handler, options());
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        .await
        .unwrap();
    entered.recv().await.unwrap();

    serving.drain();
    release.send(()).await.unwrap();
    let response = read_response(&mut client).await;
    let closed = serving.closed().await;

    assert!(response.has_header("connection", "close"), "{response:?}");
    assert_eq!(response.body, b"released");
    assert_eq!(closed.reason, CloseReason::Drain);
    assert!(is_closed(&mut client).await);
}

#[tokio::test(start_paused = true)]
async fn completes_an_http2_stream_in_flight_after_the_goaway() {
    let (handler, mut entered, release) = held_until_released();
    let (client, serving) = serve_pipe(handler, options());
    let (mut client, _) = RawH2::handshake(client).await;
    client.get(1).await;
    entered.recv().await.unwrap();

    serving.drain();
    let before = loop {
        let frame = client.next(true).await.expect("closed before a GOAWAY");
        if frame.kind == raw_h2::GOAWAY {
            break frame;
        }
        assert_ne!(frame.stream, 1, "answered before the GOAWAY: {frame:?}");
    };
    release.send(()).await.unwrap();
    let after = client.until_closed().await;
    let closed = serving.closed().await;

    assert_eq!(before.kind, raw_h2::GOAWAY);
    assert!(
        after
            .iter()
            .any(|frame| frame.stream == 1 && frame.flags & raw_h2::END_STREAM != 0),
        "{after:?}"
    );
    assert_eq!(closed.reason, CloseReason::Drain);
}

#[tokio::test(start_paused = true)]
async fn answers_a_request_sent_within_the_grace_with_connection_close() {
    let (mut client, serving) = serve_pipe(hello(), options());
    get(&mut client).await;

    serving.drain();
    tokio::time::sleep(DRAIN_IDLE_GRACE / 2).await;
    let response = get(&mut client).await;
    let closed = serving.closed().await;

    assert!(response.has_header("connection", "close"), "{response:?}");
    assert_eq!(closed.reason, CloseReason::Drain);
    assert_eq!(closed.requests, 2);
}

#[tokio::test(start_paused = true)]
async fn closes_an_http1_connection_with_nothing_in_flight_once_the_grace_is_over() {
    let (mut client, serving) = serve_pipe(hello(), options());
    get(&mut client).await;
    let asked = Instant::now();

    serving.drain();
    let closed = serving.closed().await;

    assert_eq!(closed.reason, CloseReason::Drain);
    assert_about(asked.elapsed(), DRAIN_IDLE_GRACE);
    assert!(is_closed(&mut client).await);
}

#[tokio::test(start_paused = true)]
async fn sends_an_http2_connection_with_nothing_in_flight_a_goaway_once_the_grace_is_over() {
    let (client, serving) = serve_pipe(hello(), options());
    let (mut client, _) = RawH2::handshake(client).await;
    let asked = Instant::now();

    serving.drain();
    let frames = client.until_closed().await;
    let closed = serving.closed().await;

    assert!(
        frames.iter().any(|frame| frame.kind == raw_h2::GOAWAY),
        "{frames:?}"
    );
    assert_eq!(closed.reason, CloseReason::Drain);
    assert_about(asked.elapsed(), DRAIN_IDLE_GRACE);
}

#[tokio::test(start_paused = true)]
async fn drains_a_connection_served_after_the_drain_began() {
    let (_client, server) = tokio::io::duplex(64 * 1024);
    let (_drain, drain_rx) = watch::channel(true);
    let started = Instant::now();

    let closed = server::serve(server, hello(), options(), drain_rx).await;

    assert_eq!(closed.reason, CloseReason::Drain);
    assert_about(started.elapsed(), DRAIN_IDLE_GRACE);
}

#[tokio::test(start_paused = true)]
async fn drains_a_connection_whose_drain_sender_is_gone() {
    let (mut client, serving) = serve_pipe(hello(), options());
    get(&mut client).await;
    let asked = Instant::now();

    let server_support::Serving { drain, closed } = serving;
    drop(drain);
    let closed = closed.await.unwrap();

    assert_eq!(closed.reason, CloseReason::Drain);
    assert_about(asked.elapsed(), DRAIN_IDLE_GRACE);
}
