//! What the client tests share: servers on `127.0.0.1:0` (HTTP/1.1, HTTP/2
//! with prior knowledge, TLS with ALPN, and raw sockets that misbehave), a
//! private certificate authority, bodies fed frame by frame, and the
//! client's options.
#![allow(dead_code)] // Each test file uses part of this.

use netkit_http::body::{self, Body, BoxBody, BoxError, Frame, Incoming};
use netkit_http::client::Options;
use netkit_http::{Bytes, HeaderMap, Request, Response, Uri, Version};
use netkit_tls::{Connector, ConnectorOptions, Identity, Trust};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsAcceptor;

/// How long a test waits for something that should happen at once before
/// it fails.
pub const PATIENCE: Duration = Duration::from_secs(5);

/// A connector that verifies nothing.
pub fn unverified() -> Connector {
    connector(Trust::Unverified, None)
}

pub fn connector(trust: Trust, identity: Option<Identity>) -> Connector {
    Connector::new(ConnectorOptions { trust, identity }).unwrap()
}

/// Options keeping up to 8 idle connections per server forever, giving up
/// on a connection after a second, without a cap.
pub fn options(tls: Connector) -> Options {
    Options {
        idle_per_host: 8,
        idle_timeout: None,
        connect_timeout: Some(Duration::from_secs(1)),
        http2_keep_alive: None,
        max_connections: None,
        tls,
        address_ttl: Duration::from_secs(60),
    }
}

/// A `GET` of `target` with no body.
pub fn get(target: &str) -> Request<BoxBody> {
    Request::builder().uri(target).body(body::empty()).unwrap()
}

/// The whole body of `response`, as text.
pub async fn text(response: Response<Incoming>) -> String {
    let bytes = body::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// A body whose frames are fed through the [`Feed`] that comes with it.
pub struct Fed(mpsc::Receiver<Result<Frame<Bytes>, BoxError>>);

/// Feeds a [`Fed`] body; dropping it ends the body.
pub type Feed = mpsc::Sender<Result<Frame<Bytes>, BoxError>>;

pub fn fed() -> (Feed, BoxBody) {
    let (feed, frames) = mpsc::channel(8);
    (feed, body::boxed(Fed(frames)))
}

impl Body for Fed {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.0.poll_recv(cx)
    }
}

/// A body of `data` ended by `trailers`.
pub fn with_trailers(data: &'static str, trailers: HeaderMap) -> BoxBody {
    let (feed, body) = fed();
    feed.try_send(Ok(Frame::data(Bytes::from_static(data.as_bytes()))))
        .unwrap();
    feed.try_send(Ok(Frame::trailers(trailers))).unwrap();
    body
}

/// A certificate authority, made for one test.
pub struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

/// A certificate issued by a [`Ca`], with its key.
pub struct Issued {
    pub cert: rcgen::Certificate,
    pub key: KeyPair,
}

impl Ca {
    pub fn new() -> Ca {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        Ca { cert, key }
    }

    pub fn pem(&self) -> Vec<u8> {
        self.cert.pem().into_bytes()
    }

    pub fn der(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }

    /// A server certificate for `names`.
    pub fn server(&self, names: &[&str]) -> Issued {
        self.issue(names, ExtendedKeyUsagePurpose::ServerAuth)
    }

    /// A client certificate for `name`.
    pub fn client(&self, name: &str) -> Issued {
        self.issue(&[name], ExtendedKeyUsagePurpose::ClientAuth)
    }

    fn issue(&self, names: &[&str], usage: ExtendedKeyUsagePurpose) -> Issued {
        let names: Vec<String> = names.iter().map(|name| name.to_string()).collect();
        let mut params = CertificateParams::new(names).unwrap();
        params.extended_key_usages = vec![usage];
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.cert, &self.key).unwrap();
        Issued { cert, key }
    }
}

impl Issued {
    pub fn der(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }

    pub fn identity(&self) -> Identity {
        Identity {
            cert_chain_pem: self.cert.pem().into_bytes(),
            key_pem: self.key.serialize_pem().into_bytes(),
        }
    }

    fn key_der(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.serialize_der()))
    }
}

/// TLS on the server side: its certificate, the protocols it speaks by
/// ALPN, and the authority client certificates must come from, if it asks
/// for one.
pub struct ServerTls {
    pub cert: Issued,
    pub alpn: Vec<&'static [u8]>,
    pub client_ca: Option<CertificateDer<'static>>,
}

impl ServerTls {
    /// `cert`, speaking HTTP/2 and HTTP/1.1, asking for no client
    /// certificate.
    pub fn new(cert: Issued) -> ServerTls {
        ServerTls {
            cert,
            alpn: vec![b"h2", b"http/1.1"],
            client_ca: None,
        }
    }

    /// What a server with this TLS speaks.
    pub fn wire(&self) -> Wire {
        Wire::Tls(self.acceptor())
    }

    fn acceptor(&self) -> TlsAcceptor {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap();
        let builder = match &self.client_ca {
            Some(ca) => {
                let mut roots = rustls::RootCertStore::empty();
                roots.add(ca.clone()).unwrap();
                let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                    roots.into(),
                    provider,
                )
                .build()
                .unwrap();
                builder.with_client_cert_verifier(verifier)
            }
            None => builder.with_no_client_auth(),
        };
        let mut config = builder
            .with_single_cert(vec![self.cert.der()], self.cert.key_der())
            .unwrap();
        config.alpn_protocols = self.alpn.iter().map(|id| id.to_vec()).collect();
        TlsAcceptor::from(Arc::new(config))
    }
}

/// What a server speaks.
pub enum Wire {
    Http1,
    H2c,
    /// TLS (see [`ServerTls::wire`]), then HTTP/2 if ALPN settled on it,
    /// else HTTP/1.1.
    Tls(TlsAcceptor),
}

/// A request as the server saw it.
#[derive(Debug, Clone)]
pub struct Seen {
    pub version: Version,
    pub uri: Uri,
    pub headers: HeaderMap,
    /// The certificate the client presented, if any.
    pub client_certificate: Option<CertificateDer<'static>>,
}

/// A server running in the background. Its counters can be waited on.
pub struct Server {
    pub address: SocketAddr,
    /// Connections accepted so far.
    pub accepted: watch::Receiver<usize>,
    /// Connections open now.
    pub open: watch::Receiver<usize>,
    /// Requests received so far, in order.
    pub seen: Arc<Mutex<Vec<Seen>>>,
    seen_count: watch::Receiver<usize>,
}

impl Server {
    pub fn authority(&self) -> String {
        self.address.to_string()
    }

    pub fn port(&self) -> u16 {
        self.address.port()
    }

    pub fn accepted(&self) -> usize {
        *self.accepted.borrow()
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// Wait until as many connections as `count` are open.
    pub async fn open_becomes(&self, count: usize) {
        wait_for(&self.open, count).await;
    }

    /// Wait until `count` requests have arrived.
    pub async fn has_seen(&self, count: usize) {
        wait_for(&self.seen_count, count).await;
    }
}

async fn wait_for(value: &watch::Receiver<usize>, expected: usize) {
    let mut value = value.clone();
    let reached = tokio::time::timeout(PATIENCE, value.wait_for(|now| *now == expected))
        .await
        .is_ok();
    assert!(
        reached,
        "still {} after {PATIENCE:?}, waiting for {expected}",
        *value.borrow()
    );
}

/// A response with status 200 and `text` as its body.
pub fn ok(text: &'static str) -> Response<BoxBody> {
    Response::new(body::full(text))
}

/// A server answering every request with `handler`'s response.
pub async fn serve<H, F>(wire: Wire, handler: H) -> Server
where
    H: Fn(Request<Incoming>) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Response<BoxBody>> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (accepted_tx, accepted) = watch::channel(0);
    let (open_tx, open) = watch::channel(0);
    let (seen_count_tx, seen_count) = watch::channel(0);
    let open_tx = Arc::new(open_tx);
    let seen_count_tx = Arc::new(seen_count_tx);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let acceptor = match &wire {
        Wire::Tls(acceptor) => Some(acceptor.clone()),
        _ => None,
    };
    let h2c = matches!(wire, Wire::H2c);
    let server_seen = seen.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            accepted_tx.send_modify(|n| *n += 1);
            open_tx.send_modify(|n| *n += 1);
            let (handler, open_tx, seen, seen_count_tx) = (
                handler.clone(),
                open_tx.clone(),
                server_seen.clone(),
                seen_count_tx.clone(),
            );
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let connection = Connection {
                    handler,
                    seen,
                    seen_count: seen_count_tx,
                };
                match acceptor {
                    None if h2c => connection.http2(tcp, None).await,
                    None => connection.http1(tcp, None).await,
                    Some(acceptor) => {
                        if let Ok(tls) = acceptor.accept(tcp).await {
                            let session = tls.get_ref().1;
                            let certificate = session
                                .peer_certificates()
                                .and_then(|chain| chain.first().cloned());
                            if session.alpn_protocol() == Some(b"h2") {
                                connection.http2(tls, certificate).await;
                            } else {
                                connection.http1(tls, certificate).await;
                            }
                        }
                    }
                }
                open_tx.send_modify(|n| *n -= 1);
            });
        }
    });
    Server {
        address,
        accepted,
        open,
        seen,
        seen_count,
    }
}

/// A server's answer to one request, on its way.
type Answer = Pin<Box<dyn Future<Output = Result<Response<BoxBody>, Infallible>> + Send>>;

/// One accepted connection, served until it closes.
struct Connection<H> {
    handler: H,
    seen: Arc<Mutex<Vec<Seen>>>,
    seen_count: Arc<watch::Sender<usize>>,
}

impl<H, F> Connection<H>
where
    H: Fn(Request<Incoming>) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Response<BoxBody>> + Send + 'static,
{
    fn service(
        self,
        certificate: Option<CertificateDer<'static>>,
    ) -> impl hyper::service::Service<
        Request<Incoming>,
        Response = Response<BoxBody>,
        Error = Infallible,
        Future = Answer,
    > {
        hyper::service::service_fn(move |request: Request<Incoming>| {
            self.seen.lock().unwrap().push(Seen {
                version: request.version(),
                uri: request.uri().clone(),
                headers: request.headers().clone(),
                client_certificate: certificate.clone(),
            });
            self.seen_count.send_modify(|n| *n += 1);
            let answer = (self.handler)(request);
            Box::pin(async move { Ok::<_, Infallible>(answer.await) }) as Answer
        })
    }

    async fn http1<IO>(self, io: IO, certificate: Option<CertificateDer<'static>>)
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(hyper_util::rt::TokioIo::new(io), self.service(certificate))
            .await;
    }

    async fn http2<IO>(self, io: IO, certificate: Option<CertificateDer<'static>>)
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection(hyper_util::rt::TokioIo::new(io), self.service(certificate))
            .await;
    }
}

/// A server that reads one request head on each connection, writes
/// `answer` and then hangs up: with a reset (`SO_LINGER` 0) when `reset`,
/// else with an orderly close.
pub async fn raw(answer: &'static [u8], reset: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut tcp, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                read_head(&mut tcp).await;
                let _ = tcp.write_all(answer).await;
                let _ = tcp.flush().await;
                if reset {
                    // A linger of zero turns the close into a reset; the
                    // close does not block, as nothing is left to send.
                    #[allow(deprecated)]
                    let _ = tcp.set_linger(Some(Duration::ZERO));
                }
                drop(tcp);
            });
        }
    });
    address
}

/// Read until the end of a request head.
async fn read_head(tcp: &mut TcpStream) {
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        match tcp.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => head.extend_from_slice(&buf[..n]),
        }
    }
}

/// The address of a port nothing listens on.
pub fn closed() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}
