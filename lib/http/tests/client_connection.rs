//! The single-connection client: one connection, opened on demand, used for
//! a few exchanges and closed when dropped.

mod client_support;

use client_support::*;
use netkit_http::client::{Connection, ConnectionOptions, FailureKind, Protocol};
use netkit_http::{Version, header};
use std::time::Duration;

fn plain(protocol: Protocol) -> ConnectionOptions {
    ConnectionOptions {
        protocol,
        tls: None,
        connect_timeout: Some(Duration::from_secs(1)),
    }
}

#[tokio::test]
async fn exchanges_over_http11() {
    let server = serve(Wire::Http1, |_| async { ok("hello") }).await;
    let mut connection = Connection::open("127.0.0.1", server.port(), &plain(Protocol::Http11))
        .await
        .unwrap();

    let response = connection.send(get("/health")).await.unwrap();

    assert_eq!(text(response).await, "hello");
    let seen = &server.seen()[0];
    assert_eq!(seen.version, Version::HTTP_11);
    assert_eq!(seen.uri, "/health");
    assert_eq!(seen.headers[header::HOST], server.authority().as_str());
}

#[tokio::test]
async fn exchanges_over_http2_with_prior_knowledge() {
    let server = serve(Wire::H2c, |_| async { ok("hello") }).await;
    let mut connection = Connection::open("127.0.0.1", server.port(), &plain(Protocol::Http2))
        .await
        .unwrap();

    let response = connection.send(get("/health")).await.unwrap();

    assert_eq!(text(response).await, "hello");
    let seen = &server.seen()[0];
    assert_eq!(seen.version, Version::HTTP_2);
    assert_eq!(
        seen.uri,
        format!("http://{}/health", server.authority()).as_str()
    );
}

#[tokio::test]
async fn exchanges_over_unverified_tls_with_alpn_h2() {
    let ca = Ca::new();
    let tls = ServerTls::new(ca.server(&["elsewhere.test"]));
    let server = serve(tls.wire(), |_| async { ok("hello") }).await;
    let options = ConnectionOptions {
        tls: Some(unverified()),
        ..plain(Protocol::Http2)
    };
    let mut connection = Connection::open("127.0.0.1", server.port(), &options)
        .await
        .unwrap();

    let response = connection.send(get("/health")).await.unwrap();

    assert_eq!(text(response).await, "hello");
    let seen = &server.seen()[0];
    assert_eq!(seen.version, Version::HTTP_2);
    assert_eq!(seen.uri.scheme_str(), Some("https"));
}

#[tokio::test]
async fn carries_several_exchanges_on_one_connection() {
    let server = serve(Wire::Http1, |_| async { ok("hello") }).await;
    let mut connection = Connection::open("127.0.0.1", server.port(), &plain(Protocol::Http11))
        .await
        .unwrap();

    for _ in 0..2 {
        let response = connection.send(get("/")).await.unwrap();
        text(response).await;
    }

    assert_eq!(server.accepted(), 1);
}

#[tokio::test]
async fn dropping_it_closes_the_connection() {
    let server = serve(Wire::H2c, |_| async { ok("hello") }).await;
    let mut connection = Connection::open("127.0.0.1", server.port(), &plain(Protocol::Http2))
        .await
        .unwrap();
    text(connection.send(get("/")).await.unwrap()).await;
    server.open_becomes(1).await;

    drop(connection);

    server.open_becomes(0).await;
}

#[tokio::test]
async fn a_request_target_cannot_send_it_elsewhere() {
    let server = serve(Wire::Http1, |_| async { ok("hello") }).await;
    let mut connection = Connection::open("127.0.0.1", server.port(), &plain(Protocol::Http11))
        .await
        .unwrap();

    connection
        .send(get("http://elsewhere.test:1/path?query=1"))
        .await
        .unwrap();

    let seen = &server.seen()[0];
    assert_eq!(seen.uri, "/path?query=1");
    assert_eq!(seen.headers[header::HOST], server.authority().as_str());
}

#[tokio::test]
async fn a_closed_port_is_connect_refused() {
    let failure = Connection::open("127.0.0.1", closed().port(), &plain(Protocol::Http11))
        .await
        .err()
        .unwrap();

    assert_eq!(failure.kind(), FailureKind::ConnectRefused, "{failure}");
}

#[tokio::test]
async fn http2_over_tls_fails_on_a_server_that_speaks_only_http11() {
    let ca = Ca::new();
    let mut tls = ServerTls::new(ca.server(&["127.0.0.1"]));
    tls.alpn = vec![b"http/1.1"];
    let server = serve(tls.wire(), |_| async { ok("hello") }).await;
    let options = ConnectionOptions {
        tls: Some(unverified()),
        ..plain(Protocol::Http2)
    };

    let failure = Connection::open("127.0.0.1", server.port(), &options)
        .await
        .err()
        .unwrap();

    assert_eq!(failure.kind(), FailureKind::Tls, "{failure}");
}

#[tokio::test]
async fn a_server_closing_before_answering_is_a_reset() {
    let server = raw(b"", false).await;
    let mut connection = Connection::open("127.0.0.1", server.port(), &plain(Protocol::Http11))
        .await
        .unwrap();

    let failure = connection.send(get("/")).await.unwrap_err();

    assert_eq!(failure.kind(), FailureKind::Reset, "{failure}");
}
