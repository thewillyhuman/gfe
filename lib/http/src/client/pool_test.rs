//! What needs a scripted resolver, which only the crate can inject. The
//! rest of the client is tested end to end in `tests/client_*.rs`.

use super::*;
use crate::body::empty;
use crate::client::FailureKind;
use netkit_dns::Resolve;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A resolver that sends every name to 127.0.0.1, or never answers, and
/// counts its lookups.
#[derive(Debug, Clone, Default)]
struct Scripted {
    lookups: Arc<AtomicUsize>,
    hangs: bool,
}

impl Resolve for Scripted {
    async fn resolve(&self, _host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        if self.hangs {
            std::future::pending::<()>().await;
        }
        Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
    }
}

fn options() -> Options {
    Options {
        idle_per_host: 0,
        idle_timeout: None,
        connect_timeout: Some(Duration::from_millis(50)),
        http2_keep_alive: None,
        max_connections: None,
        tls: netkit_tls::Connector::new(netkit_tls::ConnectorOptions {
            trust: netkit_tls::Trust::Unverified,
            identity: None,
        })
        .unwrap(),
        address_ttl: Duration::from_secs(60),
    }
}

fn client(resolver: &Scripted) -> Client {
    let lookup = Arc::new(Cache::new(resolver.clone(), Duration::from_secs(60)));
    Client::with_lookup(options(), lookup)
}

/// The port of an HTTP/1.1 server answering every request with 200.
async fn server() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let answer = hyper::service::service_fn(|_request| async {
                    Ok::<_, std::convert::Infallible>(Response::new(empty()))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), answer)
                    .await;
            });
        }
    });
    port
}

fn get() -> Request<BoxBody> {
    Request::builder().uri("/").body(empty()).unwrap()
}

#[tokio::test]
async fn looks_a_named_host_up_through_the_cache() {
    let port = server().await;
    let resolver = Scripted::default();
    let client = client(&resolver);
    let authority = format!("server.test:{port}");

    let first = client.send(Scheme::Http, &authority, get()).await;
    let second = client.send(Scheme::Http, &authority, get()).await;

    assert!(first.is_ok() && second.is_ok());
    assert_eq!(resolver.lookups.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn never_looks_up_an_ip_address() {
    let port = server().await;
    let resolver = Scripted::default();
    let client = client(&resolver);

    let response = client
        .send(Scheme::Http, &format!("127.0.0.1:{port}"), get())
        .await;

    assert!(response.is_ok(), "{:?}", response.err());
    assert_eq!(resolver.lookups.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_connection_not_open_within_the_connect_timeout_is_a_connect_timeout() {
    let resolver = Scripted {
        hangs: true,
        ..Scripted::default()
    };
    let client = client(&resolver);

    let failure = client
        .send(Scheme::Http, "server.test:80", get())
        .await
        .unwrap_err();

    assert_eq!(failure.kind(), FailureKind::ConnectTimeout, "{failure}");
    assert_eq!(client.open_connections(), 0);
}
