//! Backends for the tests of the probes and the checker: real servers on
//! `127.0.0.1:0` (hyper, which production code does not use), speaking
//! HTTP/1.1 or HTTP/2 with or without TLS, whose answer a test can change.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::convert::Infallible;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// An HTTP backend answering every request with a status a test can change.
pub(crate) struct HttpBackend {
    pub(crate) port: u16,
    status: Arc<AtomicU16>,
    host: Arc<Mutex<String>>,
    open: watch::Receiver<usize>,
}

impl HttpBackend {
    /// Answer every request from now on with `status`.
    pub(crate) fn answer(&self, status: u16) {
        self.status.store(status, Ordering::SeqCst);
    }

    /// The `Host` header of the last request: empty before the first one,
    /// or when it had none.
    pub(crate) fn last_host(&self) -> String {
        self.host.lock().expect("not poisoned").clone()
    }

    /// Wait until no connection to the backend is open any more.
    pub(crate) async fn all_connections_closed(&self) {
        let mut open = self.open.clone();
        open.wait_for(|open| *open == 0)
            .await
            .expect("the backend runs as long as the test");
    }
}

/// Where backends listen unless a test says otherwise.
const LOOPBACK: &str = "127.0.0.1";

/// A cleartext HTTP/1.1 backend answering `status`.
pub(crate) async fn http(status: u16) -> HttpBackend {
    http_at(LOOPBACK, status).await
}

/// [`http`], listening on the first address `host` resolves to.
pub(crate) async fn http_at(host: &str, status: u16) -> HttpBackend {
    serve_http(host, status, None).await
}

/// An HTTP/1.1 backend over TLS, with a self-signed certificate for
/// `localhost`, answering `status`.
pub(crate) async fn https(status: u16) -> HttpBackend {
    https_at(LOOPBACK, status).await
}

/// [`https`], listening on the first address `host` resolves to.
pub(crate) async fn https_at(host: &str, status: u16) -> HttpBackend {
    serve_http(host, status, Some(tls_acceptor())).await
}

async fn serve_http(
    host: &str,
    status: u16,
    tls: Option<tokio_rustls::TlsAcceptor>,
) -> HttpBackend {
    let status = Arc::new(AtomicU16::new(status));
    let last_host = Arc::new(Mutex::new(String::new()));
    let (answer, record) = (status.clone(), last_host.clone());
    let (port, open) = serve(host, tls, move |request| {
        let host = request
            .headers()
            .get(hyper::header::HOST)
            .and_then(|host| host.to_str().ok())
            .unwrap_or_default();
        *record.lock().expect("not poisoned") = host.to_string();
        let status = answer.load(Ordering::SeqCst);
        let mut response = hyper::Response::new(Full::new(Bytes::from("ok")));
        *response.status_mut() = hyper::StatusCode::from_u16(status).expect("a valid status");
        response.map(|body| body.map_err(|never| match never {}).boxed())
    })
    .await;
    HttpBackend {
        port,
        status,
        host: last_host,
        open,
    }
}

/// A gRPC server speaking the health-checking protocol, over TLS (h2 by
/// ALPN) or cleartext HTTP/2. It reports `status` (a `ServingStatus`
/// value), or, given `None`, fails the call with `UNIMPLEMENTED` as a
/// server without a health service does.
pub(crate) async fn grpc_health(status: Option<u8>, tls: bool) -> u16 {
    let message = match status {
        Some(status) => vec![0, 0, 0, 0, 2, 0x08, status],
        None => Vec::new(),
    };
    grpc(message, if status.is_some() { "0" } else { "12" }, tls).await
}

/// A gRPC server answering every call with `message` as the body of a
/// successful call, whatever it holds.
pub(crate) async fn grpc_answering(message: &'static [u8]) -> u16 {
    grpc(message.to_vec(), "0", false).await
}

/// A gRPC server answering every call with `message` and the call status
/// `call_status` in the trailers.
async fn grpc(message: Vec<u8>, call_status: &'static str, tls: bool) -> u16 {
    let (port, _) = serve(LOOPBACK, tls.then(tls_acceptor), move |_| {
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("grpc-status", call_status.parse().expect("a valid header"));
        let body = Full::new(Bytes::from(message.clone()))
            .with_trailers(async move { Some(Ok::<_, Infallible>(trailers)) });
        hyper::Response::builder()
            .header("content-type", "application/grpc")
            .body(body.boxed())
            .expect("a valid response")
    })
    .await;
    port
}

/// A backend that accepts connections and never answers on them.
pub(crate) async fn silent() -> u16 {
    let listener = TcpListener::bind((LOOPBACK, 0)).await.expect("bind");
    let port = listener.local_addr().expect("bound").port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    port
}

/// A port nothing listens on.
pub(crate) async fn closed_port() -> u16 {
    let listener = TcpListener::bind((LOOPBACK, 0)).await.expect("bind");
    listener.local_addr().expect("bound").port()
}

type Body = http_body_util::combinators::BoxBody<Bytes, Infallible>;

/// Serve `respond` on a new port of `host`, HTTP/1.1 or HTTP/2 (prior
/// knowledge or ALPN), over `tls` when given. Returns the port, and the
/// number of connections open, kept up to date.
async fn serve<F>(
    host: &str,
    tls: Option<tokio_rustls::TlsAcceptor>,
    respond: F,
) -> (u16, watch::Receiver<usize>)
where
    F: Fn(&hyper::Request<Incoming>) -> hyper::Response<Body> + Clone + Send + Sync + 'static,
{
    let listener = TcpListener::bind((host, 0)).await.expect("bind");
    let port = listener.local_addr().expect("bound").port();
    let (open, watched) = watch::channel(0usize);
    let open = Arc::new(open);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (tls, respond, open) = (tls.clone(), respond.clone(), open.clone());
            open.send_modify(|open| *open += 1);
            tokio::spawn(async move {
                serve_connection(stream, tls, respond).await;
                open.send_modify(|open| *open -= 1);
            });
        }
    });
    (port, watched)
}

/// Serve one connection until the client closes it.
async fn serve_connection<F>(stream: TcpStream, tls: Option<tokio_rustls::TlsAcceptor>, respond: F)
where
    F: Fn(&hyper::Request<Incoming>) -> hyper::Response<Body> + Send + Sync + 'static,
{
    let service = service_fn(move |request| {
        let response = respond(&request);
        async move { Ok::<_, Infallible>(response) }
    });
    let builder = auto::Builder::new(TokioExecutor::new());
    let _ = match tls {
        Some(acceptor) => match acceptor.accept(stream).await {
            Ok(tls) => builder.serve_connection(TokioIo::new(tls), service).await,
            Err(_) => return,
        },
        None => {
            builder
                .serve_connection(TokioIo::new(stream), service)
                .await
        }
    };
}

/// A TLS acceptor with a self-signed certificate for `localhost`, offering
/// HTTP/2 and HTTP/1.1 by ALPN.
fn tls_acceptor() -> tokio_rustls::TlsAcceptor {
    let generated =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("a certificate");
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(generated.key_pair.serialize_der().into());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_no_client_auth()
        .with_single_cert(vec![generated.cert.der().clone()], key)
        .expect("a certificate and its key");
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}
