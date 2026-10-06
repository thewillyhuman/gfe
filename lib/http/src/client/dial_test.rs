use super::*;
use netkit_dns::{Cache, Resolve};
use std::sync::atomic::{AtomicUsize, Ordering};

/// A resolver that sends every name to 127.0.0.1, or to nowhere when told
/// to, and counts its lookups.
#[derive(Debug, Default)]
struct Scripted {
    lookups: AtomicUsize,
    answer: Answer,
}

#[derive(Debug, Default, Clone, Copy)]
enum Answer {
    #[default]
    Loopback,
    Fails,
    Never,
}

impl Resolve for Scripted {
    async fn resolve(&self, _host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        match self.answer {
            Answer::Loopback => Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))]),
            Answer::Fails => Err(io::Error::other("no such host")),
            Answer::Never => std::future::pending().await,
        }
    }
}

fn dialer(answer: Answer, connect_timeout: Option<Duration>) -> Dialer {
    let resolver = Scripted {
        answer,
        ..Scripted::default()
    };
    Dialer::new(
        Arc::new(Cache::new(resolver, Duration::from_secs(60))),
        connect_timeout,
    )
}

/// The port of a listener that was closed: connecting to it is refused.
fn closed_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

#[tokio::test]
async fn connects_to_the_address_a_name_resolves_to() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let dialer = dialer(Answer::Loopback, None);

    let stream = dialer.open("server.test", port, None).await;

    assert!(stream.is_ok(), "{:?}", stream.err());
    assert!(listener.accept().await.is_ok());
}

#[tokio::test]
async fn sets_no_delay_on_the_connection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let stream = dialer(Answer::Loopback, None)
        .open("127.0.0.1", port, None)
        .await
        .unwrap();

    let Stream::Plain(tcp) = stream else {
        panic!("no TLS was asked for");
    };
    assert!(tcp.nodelay().unwrap());
}

#[tokio::test]
async fn a_name_that_does_not_resolve_is_a_resolve_error() {
    let error = dialer(Answer::Fails, None)
        .open("server.test", 80, None)
        .await
        .err()
        .unwrap();

    assert!(matches!(error, ConnectError::Resolve { .. }), "{error}");
    assert_eq!(error.to_string(), "resolving server.test:80");
}

#[tokio::test]
async fn a_closed_port_is_refused() {
    let port = closed_port();

    let error = dialer(Answer::Loopback, None)
        .open("127.0.0.1", port, None)
        .await
        .err()
        .unwrap();

    let ConnectError::Tcp { source, .. } = &error else {
        panic!("expected a TCP error, got {error}");
    };
    assert_eq!(source.kind(), io::ErrorKind::ConnectionRefused);
}

#[tokio::test(start_paused = true)]
async fn gives_up_once_the_connect_timeout_has_passed() {
    let error = dialer(Answer::Never, Some(Duration::from_millis(50)))
        .open("server.test", 80, None)
        .await
        .err()
        .unwrap();

    assert!(matches!(error, ConnectError::TimedOut { .. }), "{error}");
    assert_eq!(
        error.to_string(),
        "connecting to server.test:80: no connection after 50ms"
    );
}

#[test]
fn takes_the_brackets_off_an_ipv6_host() {
    assert_eq!(unbracketed("[::1]"), "::1");
    assert_eq!(unbracketed("server.test"), "server.test");
}
