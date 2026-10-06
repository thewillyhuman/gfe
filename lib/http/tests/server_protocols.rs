//! Serving HTTP/1.1 and HTTP/2 from the same call: requests, responses,
//! bodies, trailers and the HTTP/2 stream limit.
mod server_support;

use bytes::Bytes;
use netkit_http::body::{BodyExt, Frame, Incoming, full};
use netkit_http::server::{CloseReason, Options};
use netkit_http::{HeaderMap, HeaderValue, Request, Response, StatusCode, Version};
use server_support::raw_h2::{self, RawH2};
use server_support::*;
use std::future::pending;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Barrier, mpsc};

#[tokio::test]
async fn answers_an_http1_request() {
    let (mut client, _serving) = serve_pipe(hello(), options());

    let response = get(&mut client).await;

    assert!(
        response.head.starts_with("HTTP/1.1 200"),
        "{}",
        response.head
    );
    assert_eq!(response.body, b"hello");
}

#[tokio::test]
async fn answers_an_http2_request_sent_with_prior_knowledge() {
    let (client, _serving) = serve_pipe(hello(), options());
    let mut sender = h2_client(client).await;

    let response = sender.send_request(h2_get()).await.unwrap();

    assert_eq!(response.version(), Version::HTTP_2);
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "hello");
}

#[tokio::test]
async fn serves_several_http1_requests_on_one_connection() {
    let (mut client, _serving) = serve_pipe(hello(), options());

    let first = get(&mut client).await;
    let second = get(&mut client).await;
    let third = get(&mut client).await;

    for response in [first, second, third] {
        assert!(
            response.head.starts_with("HTTP/1.1 200"),
            "{}",
            response.head
        );
    }
}

#[tokio::test]
async fn serves_concurrent_http2_streams_on_one_connection() {
    // Each request is answered only once all three are being handled.
    let barrier = Arc::new(Barrier::new(3));
    let handler = Arc::new(Handle(move |_request| {
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            Response::new(full("together"))
        }
    }));
    let (client, _serving) = serve_pipe(handler, options());
    let sender = h2_client(client).await;
    let (mut a, mut b, mut c) = (sender.clone(), sender.clone(), sender);

    let responses = tokio::join!(
        a.send_request(h2_get()),
        b.send_request(h2_get()),
        c.send_request(h2_get()),
    );

    for response in [responses.0, responses.1, responses.2] {
        assert_eq!(response.unwrap().status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn counts_the_requests_it_served() {
    let (mut client, serving) = serve_pipe(hello(), options());
    get(&mut client).await;
    get(&mut client).await;

    drop(client);
    let closed = serving.closed().await;

    assert_eq!(closed.requests, 2);
}

#[tokio::test]
async fn a_connection_the_client_closes_ends_as_closed() {
    let (mut client, serving) = serve_pipe(hello(), options());
    get(&mut client).await;

    drop(client);
    let closed = serving.closed().await;

    assert_eq!(closed.reason, CloseReason::Closed);
    assert_eq!(closed.error, None);
}

#[tokio::test]
async fn tells_http2_clients_the_concurrent_stream_limit() {
    let options = Options {
        max_concurrent_streams: 7,
        ..options()
    };
    let (client, _serving) = serve_pipe(hello(), options);

    let (_client, settings) = RawH2::handshake(client).await;

    assert_eq!(
        settings.setting(raw_h2::SETTINGS_MAX_CONCURRENT_STREAMS),
        Some(7)
    );
}

#[tokio::test]
async fn refuses_a_stream_over_the_concurrent_stream_limit() {
    let options = Options {
        max_concurrent_streams: 1,
        ..options()
    };
    let handler = Arc::new(Handle(|_request| pending::<Response<_>>()));
    let (client, _serving) = serve_pipe(handler, options);
    let (mut client, _) = RawH2::handshake(client).await;

    client.get(1).await;
    client.get(3).await;
    let refused = loop {
        let frame = client.next(true).await.expect("connection closed");
        if frame.kind == raw_h2::RST_STREAM {
            break frame;
        }
    };

    assert_eq!(refused.stream, 3);
    assert_eq!(refused.error_code(), raw_h2::REFUSED_STREAM);
}

#[tokio::test]
async fn sends_response_trailers_to_http2_clients() {
    let handler = Arc::new(Handle(|_request| async {
        let (frames, body) = channel_body();
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        frames
            .send(Frame::data(Bytes::from("message")))
            .await
            .unwrap();
        frames.send(Frame::trailers(trailers)).await.unwrap();
        Response::new(body)
    }));
    let (client, _serving) = serve_pipe(handler, options());
    let mut sender = h2_client(client).await;

    let response = sender.send_request(h2_get()).await.unwrap();
    let collected = response.into_body().collect().await.unwrap();

    let trailers = collected.trailers().expect("no trailers").clone();
    assert_eq!(trailers["grpc-status"], "0");
    assert_eq!(collected.to_bytes(), "message");
}

#[tokio::test]
async fn hands_a_streamed_request_body_to_the_handler_frame_by_frame() {
    let (seen, mut seen_rx) = mpsc::channel::<Bytes>(8);
    let handler = Arc::new(Handle(move |request: Request<Incoming>| {
        let seen = seen.clone();
        async move {
            let mut body = request.into_body();
            while let Some(frame) = body.frame().await {
                if let Ok(data) = frame.unwrap().into_data() {
                    seen.send(data).await.unwrap();
                }
            }
            Response::new(full("done"))
        }
    }));
    let (client, _serving) = serve_pipe(handler, options());
    let mut sender = h2_client(client).await;
    let (frames, body) = channel_body();
    let request = Request::post("http://test/").body(body).unwrap();
    let response = tokio::spawn(sender.send_request(request));

    frames
        .send(Frame::data(Bytes::from("first")))
        .await
        .unwrap();
    let first = seen_rx.recv().await.unwrap();
    frames
        .send(Frame::data(Bytes::from("second")))
        .await
        .unwrap();
    let second = seen_rx.recv().await.unwrap();
    drop(frames);

    assert_eq!(first, "first");
    assert_eq!(second, "second");
    assert_eq!(response.await.unwrap().unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn hands_a_chunked_http1_request_body_to_the_handler() {
    let handler = Arc::new(Handle(|request: Request<Incoming>| async move {
        let body = request.into_body().collect().await.unwrap().to_bytes();
        Response::new(full(body))
    }));
    let (mut client, _serving) = serve_pipe(handler, options());

    client
        .write_all(
            b"POST / HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\r\n\
              3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n",
        )
        .await
        .unwrap();
    let response = read_response(&mut client).await;

    assert_eq!(response.body, b"abcdef");
}
