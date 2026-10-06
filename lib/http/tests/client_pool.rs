//! Connections kept and reused, closed when idle, capped; bodies streamed
//! both ways; HTTP/2 connections whose peer went silent given up on.

mod client_support;

use client_support::*;
use netkit_http::body::{self, BodyExt, BoxBody, Frame};
use netkit_http::client::{Client, FailureKind, KeepAlive, Scheme};
use netkit_http::{Bytes, HeaderMap, Request, Response};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, oneshot};

/// A server holding every answer until the test lets one through.
async fn gated() -> (Server, Arc<Semaphore>) {
    let gate = Arc::new(Semaphore::new(0));
    let server = serve(Wire::Http1, {
        let gate = gate.clone();
        move |_| {
            let gate = gate.clone();
            async move {
                gate.acquire().await.unwrap().forget();
                ok("let through")
            }
        }
    })
    .await;
    (server, gate)
}

#[tokio::test]
async fn a_second_request_reuses_the_pooled_connection() {
    let server = serve(Wire::Http1, |_| async { ok("hello") }).await;
    let client = Client::new(options(unverified()));

    for _ in 0..2 {
        let response = client
            .send(Scheme::Http, &server.authority(), get("/"))
            .await
            .unwrap();
        assert_eq!(text(response).await, "hello");
    }

    assert_eq!(server.accepted(), 1);
    assert_eq!(client.open_connections(), 1);
}

#[tokio::test]
async fn an_http2_connection_carries_concurrent_requests() {
    let server = serve(Wire::H2c, |_| async { ok("hello") }).await;
    let client = Client::new(options(unverified()));
    let authority = server.authority();

    let (first, second) = tokio::join!(
        client.send(Scheme::H2c, &authority, get("/")),
        client.send(Scheme::H2c, &authority, get("/")),
    );

    assert!(first.is_ok() && second.is_ok());
    assert_eq!(server.accepted(), 1);
}

#[tokio::test]
async fn closes_a_connection_idle_for_idle_timeout() {
    let server = serve(Wire::Http1, |_| async { ok("hello") }).await;
    let mut options = options(unverified());
    options.idle_timeout = Some(Duration::from_millis(20));
    let client = Client::new(options);

    let response = client
        .send(Scheme::Http, &server.authority(), get("/"))
        .await
        .unwrap();
    text(response).await;

    server.open_becomes(0).await;
    assert_eq!(client.open_connections(), 0);
}

#[tokio::test]
async fn keeps_no_more_idle_connections_than_idle_per_host() {
    let (server, gate) = gated().await;
    let mut options = options(unverified());
    options.idle_per_host = 1;
    let client = Client::new(options);
    let requests: Vec<_> = (0..3)
        .map(|_| {
            let (client, authority) = (client.clone(), server.authority());
            tokio::spawn(async move {
                let response = client.send(Scheme::Http, &authority, get("/")).await;
                text(response.unwrap()).await
            })
        })
        .collect();
    // Three requests in flight at once need three connections.
    server.has_seen(3).await;

    gate.add_permits(3);
    for request in requests {
        request.await.unwrap();
    }

    server.open_becomes(1).await;
    assert_eq!(client.open_connections(), 1);
}

#[tokio::test]
async fn refuses_at_once_a_connection_beyond_the_cap() {
    let (server, gate) = gated().await;
    let mut options = options(unverified());
    options.max_connections = Some(1);
    options.idle_per_host = 0;
    let client = Client::new(options);
    let busy = {
        let (client, authority) = (client.clone(), server.authority());
        tokio::spawn(async move { client.send(Scheme::Http, &authority, get("/")).await })
    };
    server.has_seen(1).await;

    let refused = client
        .send(Scheme::Http, &server.authority(), get("/"))
        .await;

    let failure = refused.unwrap_err();
    assert_eq!(failure.kind(), FailureKind::ConnectionLimit, "{failure}");
    assert_eq!(client.max_connections(), Some(1));
    assert_eq!(server.accepted(), 1);
    gate.add_permits(1);
    text(busy.await.unwrap().unwrap()).await;
    server.open_becomes(0).await;
    assert_eq!(client.open_connections(), 0);
}

#[tokio::test]
async fn reuses_a_pooled_connection_at_the_cap() {
    let server = serve(Wire::Http1, |_| async { ok("hello") }).await;
    let mut options = options(unverified());
    options.max_connections = Some(1);
    let client = Client::new(options);

    for _ in 0..2 {
        let response = client
            .send(Scheme::Http, &server.authority(), get("/"))
            .await
            .unwrap();
        text(response).await;
    }

    assert_eq!(client.open_connections(), 1);
}

#[tokio::test]
async fn streams_the_request_body() {
    // Tells the test when the first chunk has arrived, then answers with
    // everything it read.
    let (arrived_tx, arrived) = oneshot::channel::<Bytes>();
    let arrived_tx = Arc::new(std::sync::Mutex::new(Some(arrived_tx)));
    let server = serve(Wire::Http1, move |request| {
        let arrived_tx = arrived_tx.clone();
        async move {
            let mut body = request.into_body();
            let mut read = Vec::new();
            while let Some(frame) = body.frame().await {
                let data = frame.unwrap().into_data().unwrap();
                read.extend_from_slice(&data);
                if let Some(tx) = arrived_tx.lock().unwrap().take() {
                    tx.send(data).unwrap();
                }
            }
            Response::new(body::full(read))
        }
    })
    .await;
    let client = Client::new(options(unverified()));
    let (feed, request_body) = fed();
    let request = Request::builder()
        .method("POST")
        .uri("/")
        .body(request_body)
        .unwrap();
    let sending = tokio::spawn({
        let (client, authority) = (client.clone(), server.authority());
        async move { client.send(Scheme::Http, &authority, request).await }
    });

    feed.send(Ok(Frame::data(Bytes::from_static(b"first "))))
        .await
        .unwrap();
    // The server has the first chunk while the body is still open.
    assert_eq!(arrived.await.unwrap(), "first ");
    feed.send(Ok(Frame::data(Bytes::from_static(b"second"))))
        .await
        .unwrap();
    drop(feed);

    let response = sending.await.unwrap().unwrap();
    assert_eq!(text(response).await, "first second");
}

fn grpc_ok() -> HeaderMap {
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", "0".parse().unwrap());
    trailers
}

async fn trailers_arrive_over(wire: Wire, scheme: Scheme, client: Client) {
    let server = serve(wire, |_| async {
        Response::new(with_trailers("message", grpc_ok()))
    })
    .await;
    let mut request = get("/");
    *request.version_mut() = netkit_http::Version::HTTP_2;

    let response = client
        .send(scheme, &server.authority(), request)
        .await
        .unwrap();

    let collected = response.into_body().collect().await.unwrap();
    assert_eq!(collected.trailers(), Some(&grpc_ok()));
    assert_eq!(collected.to_bytes(), "message");
}

#[tokio::test]
async fn response_trailers_arrive_over_h2c() {
    let client = Client::new(options(unverified()));

    trailers_arrive_over(Wire::H2c, Scheme::H2c, client).await;
}

#[tokio::test]
async fn response_trailers_arrive_over_https() {
    let ca = Ca::new();
    let tls = ServerTls::new(ca.server(&["127.0.0.1"]));
    let client = Client::new(options(unverified()));

    trailers_arrive_over(tls.wire(), Scheme::Https, client).await;
}

/// The address of an HTTP/2 server that takes a request and then goes
/// silent without closing the connection, as a host that lost power does.
async fn dies_after_the_request() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let (seen_tx, seen) = oneshot::channel::<()>();
        let seen_tx = std::sync::Mutex::new(Some(seen_tx));
        let never = hyper::service::service_fn(move |_request| {
            if let Some(tx) = seen_tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
            std::future::pending::<Result<Response<BoxBody>, std::convert::Infallible>>()
        });
        let connection =
            hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(hyper_util::rt::TokioIo::new(tcp), never);
        tokio::pin!(connection);
        tokio::select! {
            _ = &mut connection => {}
            _ = seen => {}
        }
        // Stop driving the connection but keep its socket open: pings go
        // unanswered and nothing tells the client.
        std::future::pending::<()>().await;
    });
    authority
}

#[tokio::test]
async fn gives_up_on_an_http2_connection_whose_peer_went_silent() {
    let server = dies_after_the_request().await;
    let mut options = options(unverified());
    options.http2_keep_alive = Some(KeepAlive {
        idle: Duration::from_millis(20),
        timeout: Duration::from_millis(20),
    });
    let client = Client::new(options);

    let outcome = tokio::time::timeout(PATIENCE, client.send(Scheme::H2c, &server, get("/"))).await;

    let failure = outcome
        .expect("the silent connection is noticed")
        .unwrap_err();
    assert_eq!(failure.kind(), FailureKind::Reset, "{failure}");
}
