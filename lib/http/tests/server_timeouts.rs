//! The timers a served connection is held to: the first request head, the
//! idle timeout, and the HTTP/2 keep-alive PING. Time is paused: it jumps
//! ahead whenever nothing else is left to do.
mod server_support;

use bytes::Bytes;
use netkit_http::Response;
use netkit_http::body::Frame;
use netkit_http::server::{CLOSE_GRACE, CloseReason, Options};
use server_support::raw_h2::{self, RawH2};
use server_support::*;
use std::future::pending;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

#[tokio::test(start_paused = true)]
async fn closes_a_connection_that_sends_no_head_within_the_header_timeout() {
    let started = Instant::now();
    let (mut client, serving) = serve_pipe(hello(), options());

    let closed = serving.closed().await;

    assert_eq!(closed.reason, CloseReason::HeaderTimeout);
    assert_about(started.elapsed(), HEADER_TIMEOUT);
    assert!(is_closed(&mut client).await);
}

#[tokio::test(start_paused = true)]
async fn closes_a_connection_whose_first_head_is_sent_too_slowly() {
    let started = Instant::now();
    let (mut client, serving) = serve_pipe(hello(), options());

    client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
    let closed = serving.closed().await;

    assert_eq!(closed.reason, CloseReason::HeaderTimeout);
    assert_about(started.elapsed(), HEADER_TIMEOUT);
}

#[tokio::test(start_paused = true)]
async fn holds_a_client_slow_after_its_first_request_to_the_idle_timeout() {
    let (mut client, serving) = serve_pipe(hello(), options());
    get(&mut client).await;
    let answered = Instant::now();

    client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
    let closed = serving.closed().await;

    assert_eq!(closed.reason, CloseReason::IdleTimeout);
    assert_about(answered.elapsed(), IDLE_TIMEOUT);
}

#[tokio::test(start_paused = true)]
async fn closes_an_idle_http1_connection_after_the_idle_timeout() {
    let (mut client, serving) = serve_pipe(hello(), options());
    get(&mut client).await;
    let answered = Instant::now();

    let closed = serving.closed().await;

    assert_eq!(closed.reason, CloseReason::IdleTimeout);
    assert_about(answered.elapsed(), IDLE_TIMEOUT);
    assert!(is_closed(&mut client).await);
}

#[tokio::test(start_paused = true)]
async fn sends_an_idle_http2_connection_a_goaway_before_closing_it() {
    let (client, serving) = serve_pipe(hello(), options());
    let (mut client, _) = RawH2::handshake(client).await;
    client.get(1).await;
    let answered = loop {
        let frame = client.next(true).await.expect("closed before answering");
        if frame.stream == 1 && frame.flags & raw_h2::END_STREAM != 0 {
            break Instant::now();
        }
    };

    let frames = client.until_closed().await;
    let closed = serving.closed().await;

    assert!(
        frames.iter().any(|frame| frame.kind == raw_h2::GOAWAY),
        "{frames:?}"
    );
    assert_eq!(closed.reason, CloseReason::IdleTimeout);
    assert_about(answered.elapsed(), IDLE_TIMEOUT);
}

#[tokio::test(start_paused = true)]
async fn closes_an_idle_http2_connection_at_an_idle_timeout_shorter_than_the_header_timeout() {
    let idle_timeout = HEADER_TIMEOUT / 4;
    let (client, serving) = serve_pipe(
        hello(),
        Options {
            idle_timeout,
            ..options()
        },
    );
    let (mut client, _) = RawH2::handshake(client).await;
    client.get(1).await;
    let answered = loop {
        let frame = client.next(true).await.expect("closed before answering");
        if frame.stream == 1 && frame.flags & raw_h2::END_STREAM != 0 {
            break Instant::now();
        }
    };

    let frames = client.until_closed().await;
    let closed = serving.closed().await;

    assert!(
        frames.iter().any(|frame| frame.kind == raw_h2::GOAWAY),
        "{frames:?}"
    );
    assert_eq!(closed.reason, CloseReason::IdleTimeout);
    assert_about(answered.elapsed(), idle_timeout);
}

#[tokio::test(start_paused = true)]
async fn does_not_time_out_while_a_response_body_is_being_sent() {
    let (body_tx, mut body_rx) = tokio::sync::mpsc::channel(1);
    let handler = Arc::new(Handle(move |_request| {
        let body_tx = body_tx.clone();
        async move {
            let (frames, body) = channel_body();
            body_tx.send(frames).await.unwrap();
            Response::new(body)
        }
    }));
    let (mut client, serving) = serve_pipe(handler, options());
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        .await
        .unwrap();
    let frames = body_rx.recv().await.unwrap();
    let head = read_response(&mut client).await;

    tokio::time::sleep(IDLE_TIMEOUT * 3).await;
    let still_open = !serving.closed.is_finished();
    frames.send(Frame::data(Bytes::from("late"))).await.unwrap();
    drop(frames);

    assert!(head.has_header("transfer-encoding", "chunked"), "{head:?}");
    assert!(still_open);
    let mut chunks = vec![0; b"4\r\nlate\r\n0\r\n\r\n".len()];
    client.read_exact(&mut chunks).await.unwrap();
    assert_eq!(chunks, b"4\r\nlate\r\n0\r\n\r\n");
}

#[tokio::test(start_paused = true)]
async fn closes_an_http2_client_that_does_not_acknowledge_a_ping() {
    let handler = Arc::new(Handle(|_request| pending::<Response<_>>()));
    let (client, serving) = serve_pipe(handler, options());
    let (mut client, _) = RawH2::handshake(client).await;
    client.get(1).await;
    let asked = Instant::now();

    let ping = loop {
        let frame = client.read().await.expect("closed before any PING");
        if frame.kind == raw_h2::PING {
            break frame;
        }
    };
    let closed = serving.closed().await;

    assert_eq!(ping.flags & raw_h2::ACK, 0);
    assert_eq!(closed.reason, CloseReason::ClientUnresponsive);
    assert_about(asked.elapsed(), IDLE_TIMEOUT + KEEP_ALIVE_TIMEOUT);
}

#[tokio::test(start_paused = true)]
async fn closes_outright_a_connection_that_does_not_finish_shutting_down() {
    let (client, serving) = serve_pipe(hello(), options());
    let (mut client, _) = RawH2::handshake(client).await;
    client.get(1).await;
    let answered = loop {
        let frame = client.next(true).await.expect("closed before answering");
        if frame.stream == 1 && frame.flags & raw_h2::END_STREAM != 0 {
            break Instant::now();
        }
    };

    // The GOAWAY's PING goes unanswered, so the shutdown never completes.
    let closed = serving.closed().await;

    assert_eq!(closed.reason, CloseReason::IdleTimeout);
    assert_about(answered.elapsed(), IDLE_TIMEOUT + CLOSE_GRACE);
    drop(client);
}
