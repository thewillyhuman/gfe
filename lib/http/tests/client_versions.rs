//! Which HTTP version a request goes out over, what names the host it is
//! for, and that it reaches the server it is sent to whatever its target.

mod client_support;

use client_support::*;
use netkit_http::client::{Client, FailureKind, Scheme};
use netkit_http::{Version, header};
use netkit_tls::Trust;

async fn hello() -> Server {
    serve(Wire::Http1, |_| async { ok("hello") }).await
}

fn for_host(
    mut request: netkit_http::Request<netkit_http::body::BoxBody>,
    host: &str,
) -> netkit_http::Request<netkit_http::body::BoxBody> {
    request
        .headers_mut()
        .insert(header::HOST, host.parse().unwrap());
    request
}

#[tokio::test]
async fn http_goes_out_as_http11_with_the_callers_host() {
    let server = hello().await;
    let client = Client::new(options(unverified()));
    let mut request = for_host(get("/"), "example.org");
    *request.version_mut() = Version::HTTP_2;

    let response = client
        .send(Scheme::Http, &server.authority(), request)
        .await
        .unwrap();

    assert_eq!(text(response).await, "hello");
    let seen = &server.seen()[0];
    assert_eq!(seen.version, Version::HTTP_11);
    assert_eq!(seen.headers[header::HOST], "example.org");
}

#[tokio::test]
async fn a_request_without_host_names_the_authority() {
    let server = hello().await;
    let client = Client::new(options(unverified()));

    client
        .send(Scheme::Http, &server.authority(), get("/"))
        .await
        .unwrap();

    assert_eq!(
        server.seen()[0].headers[header::HOST],
        server.authority().as_str()
    );
}

#[tokio::test]
async fn h2c_goes_out_as_http2_named_by_the_authority_alone() {
    let server = serve(Wire::H2c, |_| async { ok("hello") }).await;
    let client = Client::new(options(unverified()));

    let response = client
        .send(
            Scheme::H2c,
            &server.authority(),
            for_host(get("/"), "example.org"),
        )
        .await
        .unwrap();

    assert_eq!(text(response).await, "hello");
    let seen = &server.seen()[0];
    assert_eq!(seen.version, Version::HTTP_2);
    assert_eq!(
        seen.uri.authority().unwrap().as_str(),
        server.authority().as_str()
    );
    assert!(!seen.headers.contains_key(header::HOST));
}

async fn tls_server(alpn: Vec<&'static [u8]>) -> (Server, Ca) {
    let ca = Ca::new();
    let mut tls = ServerTls::new(ca.server(&["127.0.0.1"]));
    tls.alpn = alpn;
    let server = serve(tls.wire(), |_| async { ok("hello") }).await;
    (server, ca)
}

fn trusting(ca: &Ca) -> Client {
    Client::new(options(connector(Trust::SystemAnd(ca.pem()), None)))
}

#[tokio::test]
async fn https_goes_out_as_http11_for_a_request_that_does_not_need_http2() {
    let (server, ca) = tls_server(vec![b"h2", b"http/1.1"]).await;
    let client = trusting(&ca);

    let response = client
        .send(
            Scheme::Https,
            &server.authority(),
            for_host(get("/"), "example.org"),
        )
        .await
        .unwrap();

    assert_eq!(text(response).await, "hello");
    let seen = &server.seen()[0];
    assert_eq!(seen.version, Version::HTTP_11);
    assert_eq!(seen.headers[header::HOST], "example.org");
}

#[tokio::test]
async fn https_negotiates_http2_for_a_request_that_needs_it() {
    let (server, ca) = tls_server(vec![b"h2", b"http/1.1"]).await;
    let client = trusting(&ca);
    let mut request = for_host(get("/"), "example.org");
    *request.version_mut() = Version::HTTP_2;

    let response = client
        .send(Scheme::Https, &server.authority(), request)
        .await
        .unwrap();

    assert_eq!(text(response).await, "hello");
    let seen = &server.seen()[0];
    assert_eq!(seen.version, Version::HTTP_2);
    assert!(!seen.headers.contains_key(header::HOST));
}

#[tokio::test]
async fn a_request_that_needs_http2_fails_on_a_server_that_speaks_only_http11() {
    let (server, ca) = tls_server(vec![b"http/1.1"]).await;
    let client = trusting(&ca);
    let mut request = get("/");
    *request.version_mut() = Version::HTTP_2;

    let failure = client
        .send(Scheme::Https, &server.authority(), request)
        .await
        .unwrap_err();

    assert_eq!(failure.kind(), FailureKind::Tls, "{failure}");
    assert!(server.seen().is_empty());
}

#[tokio::test]
async fn a_request_that_needs_http2_fails_on_a_server_without_alpn() {
    let (server, ca) = tls_server(Vec::new()).await;
    let client = trusting(&ca);
    let mut request = get("/");
    *request.version_mut() = Version::HTTP_2;

    let failure = client
        .send(Scheme::Https, &server.authority(), request)
        .await
        .unwrap_err();

    assert_eq!(failure.kind(), FailureKind::Tls, "{failure}");
    assert!(failure.to_string().contains("did not agree"), "{failure}");
}

#[tokio::test]
async fn https_speaks_http11_to_a_server_without_alpn() {
    let (server, ca) = tls_server(Vec::new()).await;
    let client = trusting(&ca);

    let response = client
        .send(Scheme::Https, &server.authority(), get("/"))
        .await
        .unwrap();

    assert_eq!(text(response).await, "hello");
}

#[tokio::test]
async fn an_absolute_target_cannot_send_the_request_elsewhere() {
    let server = hello().await;
    let client = Client::new(options(unverified()));

    client
        .send(
            Scheme::Http,
            &server.authority(),
            get("http://elsewhere.test:1/path?query=1"),
        )
        .await
        .unwrap();

    assert_eq!(server.seen()[0].uri, "/path?query=1");
}

#[tokio::test]
async fn a_target_that_looks_like_an_authority_stays_a_path() {
    let server = serve(Wire::H2c, |_| async { ok("hello") }).await;
    let client = Client::new(options(unverified()));

    client
        .send(
            Scheme::H2c,
            &server.authority(),
            get("//elsewhere.test:1/path"),
        )
        .await
        .unwrap();

    let seen = &server.seen()[0];
    assert_eq!(
        seen.uri.authority().unwrap().as_str(),
        server.authority().as_str()
    );
    assert_eq!(seen.uri.path(), "//elsewhere.test:1/path");
}

#[tokio::test]
async fn an_asterisk_target_reaches_the_server() {
    let server = hello().await;
    let client = Client::new(options(unverified()));
    let mut request = get("*");
    *request.method_mut() = netkit_http::Method::OPTIONS;

    let response = client
        .send(Scheme::Http, &server.authority(), request)
        .await;

    assert!(response.is_ok(), "{:?}", response.err());
    assert_eq!(server.seen()[0].uri, "*");
}
