//! Each way an exchange fails, and the kind it is reported as. The connect
//! timeout, which needs a lookup that never ends, is tested in
//! `src/client/pool_test.rs`; TLS refusals in `client_tls.rs`.

mod client_support;

use client_support::*;
use netkit_http::body::{self, Frame};
use netkit_http::client::{Client, FailureKind, Scheme};
use netkit_http::{Bytes, Request};
use std::error::Error;

#[tokio::test]
async fn a_closed_port_is_connect_refused() {
    let client = Client::new(options(unverified()));

    let failure = client
        .send(Scheme::Http, &closed().to_string(), get("/"))
        .await
        .unwrap_err();

    assert_eq!(failure.kind(), FailureKind::ConnectRefused, "{failure}");
    assert_eq!(client.open_connections(), 0);
}

#[tokio::test]
async fn a_name_that_does_not_resolve_is_a_connect_error() {
    let client = Client::new(options(unverified()));

    // `.invalid` never resolves (RFC 6761).
    let failure = client
        .send(Scheme::Http, "no-such-host.invalid:80", get("/"))
        .await
        .unwrap_err();

    assert_eq!(failure.kind(), FailureKind::ConnectError, "{failure}");
    assert!(
        failure
            .to_string()
            .contains("resolving no-such-host.invalid:80"),
        "{failure}"
    );
}

#[tokio::test]
async fn a_server_closing_before_answering_is_a_reset() {
    let server = raw(b"", false).await;
    let client = Client::new(options(unverified()));

    let failure = client
        .send(Scheme::Http, &server.to_string(), get("/"))
        .await
        .unwrap_err();

    assert_eq!(failure.kind(), FailureKind::Reset, "{failure}");
}

#[tokio::test]
async fn a_server_resetting_mid_response_head_is_a_reset() {
    let server = raw(b"HTTP/1.1 200 OK\r\nContent-Le", true).await;
    let client = Client::new(options(unverified()));

    let failure = client
        .send(Scheme::Http, &server.to_string(), get("/"))
        .await
        .unwrap_err();

    assert_eq!(failure.kind(), FailureKind::Reset, "{failure}");
}

#[tokio::test]
async fn an_authority_that_is_not_one_is_other() {
    let client = Client::new(options(unverified()));

    let failure = client
        .send(Scheme::Http, "not an authority", get("/"))
        .await
        .unwrap_err();

    assert_eq!(failure.kind(), FailureKind::Other, "{failure}");
    assert!(failure.source().is_some());
}

#[tokio::test]
async fn a_request_body_that_fails_is_other() {
    // Reads the whole body before answering, so that the body's failure is
    // what ends the exchange.
    let server = serve(Wire::Http1, |request| async move {
        let _ = body::BodyExt::collect(request.into_body()).await;
        ok("read")
    })
    .await;
    let client = Client::new(options(unverified()));
    let (feed, request_body) = fed();
    feed.send(Ok(Frame::data(Bytes::from_static(b"start"))))
        .await
        .unwrap();
    feed.send(Err(
        std::io::Error::from(std::io::ErrorKind::BrokenPipe).into()
    ))
    .await
    .unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/")
        .body(request_body)
        .unwrap();

    let failure = client
        .send(Scheme::Http, &server.authority(), request)
        .await
        .unwrap_err();

    assert_eq!(failure.kind(), FailureKind::Other, "{failure}");
}

#[tokio::test]
async fn the_message_says_what_happened() {
    let address = closed();
    let client = Client::new(options(unverified()));

    let failure = client
        .send(Scheme::Http, &address.to_string(), get("/"))
        .await
        .unwrap_err();

    let message = failure.to_string();
    assert!(message.starts_with("connection refused: "), "{message}");
    assert!(
        message.contains(&format!("connecting to {address}")),
        "{message}"
    );
}
