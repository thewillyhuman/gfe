//! Who `https` servers are trusted to be, and the certificate the client
//! presents to them.

mod client_support;

use client_support::*;
use netkit_http::client::{Client, FailureKind, Scheme};
use netkit_tls::Trust;

async fn server_for(ca: &Ca, names: &[&str]) -> Server {
    let tls = ServerTls::new(ca.server(names));
    serve(tls.wire(), |_| async { ok("hello") }).await
}

#[tokio::test]
async fn the_system_store_alone_refuses_a_private_authority() {
    let ca = Ca::new();
    let server = server_for(&ca, &["127.0.0.1"]).await;
    let client = Client::new(options(connector(Trust::System, None)));

    let failure = client
        .send(Scheme::Https, &server.authority(), get("/"))
        .await
        .unwrap_err();

    assert_eq!(failure.kind(), FailureKind::Tls, "{failure}");
    assert_eq!(client.open_connections(), 0);
}

#[tokio::test]
async fn an_extra_bundle_makes_a_private_authority_trusted() {
    let ca = Ca::new();
    let server = server_for(&ca, &["127.0.0.1"]).await;
    let client = Client::new(options(connector(Trust::SystemAnd(ca.pem()), None)));

    let response = client
        .send(Scheme::Https, &server.authority(), get("/"))
        .await
        .unwrap();

    assert_eq!(text(response).await, "hello");
}

#[tokio::test]
async fn a_certificate_for_another_name_is_refused() {
    let ca = Ca::new();
    let server = server_for(&ca, &["elsewhere.test"]).await;
    let client = Client::new(options(connector(Trust::SystemAnd(ca.pem()), None)));

    let failure = client
        .send(Scheme::Https, &server.authority(), get("/"))
        .await
        .unwrap_err();

    assert_eq!(failure.kind(), FailureKind::Tls, "{failure}");
}

#[tokio::test]
async fn unverified_accepts_any_certificate() {
    let ca = Ca::new();
    let server = server_for(&ca, &["elsewhere.test"]).await;
    let client = Client::new(options(unverified()));

    let response = client
        .send(Scheme::Https, &server.authority(), get("/"))
        .await
        .unwrap();

    assert_eq!(text(response).await, "hello");
}

#[tokio::test]
async fn presents_the_client_certificate_to_a_server_that_asks() {
    let ca = Ca::new();
    let client_cert = ca.client("client.test");
    let mut tls = ServerTls::new(ca.server(&["127.0.0.1"]));
    tls.client_ca = Some(ca.der());
    let server = serve(tls.wire(), |_| async { ok("hello") }).await;
    let client = Client::new(options(connector(
        Trust::SystemAnd(ca.pem()),
        Some(client_cert.identity()),
    )));

    let response = client
        .send(Scheme::Https, &server.authority(), get("/"))
        .await
        .unwrap();

    assert_eq!(text(response).await, "hello");
    assert_eq!(server.seen()[0].client_certificate, Some(client_cert.der()));
}

#[tokio::test]
async fn a_server_refusing_the_client_for_want_of_a_certificate_is_tls() {
    let ca = Ca::new();
    let mut tls = ServerTls::new(ca.server(&["127.0.0.1"]));
    tls.client_ca = Some(ca.der());
    let server = serve(tls.wire(), |_| async { ok("hello") }).await;
    let client = Client::new(options(connector(Trust::SystemAnd(ca.pem()), None)));

    let failure = client
        .send(Scheme::Https, &server.authority(), get("/"))
        .await
        .unwrap_err();

    assert_eq!(failure.kind(), FailureKind::Tls, "{failure}");
    assert!(server.seen().is_empty());
}
