//! The pooled hyper upstream client. Connection pooling, keep-alive, and
//! h1/h2 are handled by `hyper-util`'s `Client`, keyed per authority; TLS to
//! `https` upstreams is provided by a `hyper-rustls` connector using the
//! `ring` provider and webpki roots.
//!
//! The HTTP version on the upstream leg follows the pool's [`Scheme`] and
//! the request: HTTP/1.1 for `http`; for `https`, HTTP/1.1 unless the
//! request needs HTTP/2 (gRPC), which ALPN then negotiates; and HTTP/2 with
//! prior knowledge for `h2c`. Each needs a client of its own: one offering
//! only HTTP/1.1 by ALPN, one offering both, and one that never negotiates,
//! as cleartext offers no way to negotiate the version per connection.
//!
//! Over HTTP/1.1 the backend is told the host the client asked for, in
//! `Host`, as HAProxy does. Over HTTP/2 the backend is named by
//! `:authority`, which is its own address, and no `Host` is sent that would
//! contradict it.

use crate::failure::UpstreamFailure;
use crate::limit::{ConnectionLimit, LimitedConnector};
use bytes::Bytes;
use gfe_core::config::Scheme;
use gfe_core::GfeError;
use http::uri::PathAndQuery;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::header::HOST;
use hyper::{Request, Response, Version};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use std::sync::Arc;
use std::time::Duration;

/// Boxed error type carried across the proxy/upstream boundary.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The unified request body type sent to upstreams.
pub type ReqBody = BoxBody<Bytes, BoxError>;

/// Options for building the upstream client, including upstream TLS trust and
/// optional client-certificate (mTLS) material.
#[derive(Default)]
pub struct UpstreamClientOptions {
    /// Idle pooled connections per backend authority.
    pub idle_per_host: usize,
    /// How long a pooled connection may stay idle before it is closed.
    /// `None`: idle connections are kept until the backend closes them.
    pub idle_timeout: Option<Duration>,
    /// Client certificate chain (PEM) for mTLS to upstreams.
    pub client_cert_pem: Option<Vec<u8>>,
    /// Client private key (PEM) for mTLS to upstreams.
    pub client_key_pem: Option<Vec<u8>>,
    /// Extra CA bundle (PEM) trusted on top of webpki roots.
    pub extra_ca_pem: Option<Vec<u8>>,
    /// Upper bound on establishing the TCP connection to a backend. `None`
    /// leaves it to the operating system, which can take minutes.
    pub connect_timeout: Option<Duration>,
    /// Liveness checking of HTTP/2 connections to backends. `None`: a
    /// connection that dies silently is never noticed while it has nothing
    /// to send.
    pub http2_keep_alive: Option<KeepAlive>,
    /// Upper bound on the upstream connections held open, over all backends.
    /// A request that would need one more fails at once. `None`: no bound.
    pub max_connections: Option<usize>,
}

/// HTTP/2 keep-alive: a connection with requests in flight that has been
/// silent for `idle` is pinged, and closed, failing those requests, if the
/// ping is not answered within `timeout`.
#[derive(Debug, Clone, Copy)]
pub struct KeepAlive {
    pub idle: Duration,
    pub timeout: Duration,
}

/// A cloneable, pooled client for forwarding requests to upstreams.
#[derive(Clone)]
pub struct UpstreamClient {
    /// `http` pools, and `https` pools for requests that do not need HTTP/2.
    http1: Client<Connector, ReqBody>,
    /// `https` pools, for requests that need HTTP/2.
    negotiating: Client<Connector, ReqBody>,
    /// `h2c` pools.
    http2_prior_knowledge: Client<Connector, ReqBody>,
    /// Counts, and caps, the connections of all clients together.
    connections: Arc<ConnectionLimit>,
}

/// TCP, optionally TLS, under the connection limit.
type Connector = LimitedConnector<HttpsConnector<HttpConnector>>;

impl UpstreamClient {
    /// Build the client with default trust (webpki roots) and no client cert.
    /// `max_idle_per_host` bounds idle pooled connections per upstream.
    pub fn new(max_idle_per_host: usize) -> Result<Self, GfeError> {
        UpstreamClient::with_options(UpstreamClientOptions {
            idle_per_host: max_idle_per_host,
            ..Default::default()
        })
    }

    /// Build the client with explicit TLS options (extra CAs, mTLS client cert).
    pub fn with_options(opts: UpstreamClientOptions) -> Result<Self, GfeError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(ca_pem) = &opts.extra_ca_pem {
            for cert in read_certs(ca_pem)? {
                roots
                    .add(cert)
                    .map_err(|e| GfeError::Tls(format!("adding extra CA: {e}")))?;
            }
        }

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| GfeError::Tls(format!("upstream client config: {e}")))?
            .with_root_certificates(roots);

        let tls = match (&opts.client_cert_pem, &opts.client_key_pem) {
            (Some(cert_pem), Some(key_pem)) => {
                let certs = read_certs(cert_pem)?;
                let key = read_key(key_pem)?;
                builder
                    .with_client_auth_cert(certs, key)
                    .map_err(|e| GfeError::Tls(format!("upstream client cert: {e}")))?
            }
            _ => builder.with_no_client_auth(),
        };

        let idle = if opts.idle_per_host == 0 {
            32
        } else {
            opts.idle_per_host
        };

        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(opts.connect_timeout);

        let connections = ConnectionLimit::new(opts.max_connections);
        let https_http1 = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls.clone())
            .https_or_http()
            .enable_http1()
            .wrap_connector(http.clone());
        let https_http1 = LimitedConnector::new(https_http1, connections.clone());
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(http);
        let https = LimitedConnector::new(https, connections.clone());

        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .pool_max_idle_per_host(idle)
            .pool_idle_timeout(opts.idle_timeout)
            // The pool's own timer, which closes idle connections as they
            // expire; without it they are only noticed when the backend is
            // used again. `timer` is HTTP/2's.
            .pool_timer(TokioTimer::new())
            .timer(TokioTimer::new());
        if let Some(keep_alive) = opts.http2_keep_alive {
            builder
                .http2_keep_alive_interval(keep_alive.idle)
                .http2_keep_alive_timeout(keep_alive.timeout);
        }
        let http1 = builder.build(https_http1);
        let negotiating = builder.build(https.clone());
        let http2_prior_knowledge = builder.http2_only(true).build(https);

        Ok(UpstreamClient {
            http1,
            negotiating,
            http2_prior_knowledge,
            connections,
        })
    }

    /// Upstream connections currently open (or being opened), over all
    /// backends.
    pub fn open_connections(&self) -> usize {
        self.connections.open()
    }

    /// The cap on open upstream connections, if one is set.
    pub fn max_connections(&self) -> Option<usize> {
        self.connections.max()
    }

    /// Forward a request to the given upstream. The request's URI is rebuilt
    /// with `scheme://authority` preserving path and query.
    ///
    /// The request's `Host` header is expected to be the host the client
    /// asked for. It reaches the backend when the request goes out over
    /// HTTP/1.1; over HTTP/2 it is dropped, and `:authority` is the
    /// upstream authority. A request whose version is HTTP/2 needs HTTP/2
    /// (gRPC): to an `https` pool it goes out over whatever ALPN negotiates,
    /// any other request to an `https` pool over HTTP/1.1.
    pub async fn send(
        &self,
        scheme: Scheme,
        authority: &str,
        mut req: Request<ReqBody>,
    ) -> Result<Response<Incoming>, UpstreamFailure> {
        let path_and_query = req
            .uri()
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| PathAndQuery::from_static("/"));
        let needs_http2 = req.version() == Version::HTTP_2;
        let (client, uri_scheme, over_http1) = match scheme {
            Scheme::Http => (&self.http1, "http", true),
            Scheme::Https if needs_http2 => (&self.negotiating, "https", false),
            Scheme::Https => (&self.http1, "https", true),
            Scheme::H2c => (&self.http2_prior_knowledge, "http", false),
        };
        if over_http1 {
            // The client refuses an HTTP/2 request on an HTTP/1 connection.
            *req.version_mut() = Version::HTTP_11;
        } else {
            req.headers_mut().remove(HOST);
        }
        // Built from its parts, so that no request target can run into the
        // authority and change the backend the request goes to.
        let uri = hyper::Uri::builder()
            .scheme(uri_scheme)
            .authority(authority)
            .path_and_query(path_and_query)
            .build()
            .map_err(|e| UpstreamFailure::other(Box::new(e)))?;
        *req.uri_mut() = uri;

        client
            .request(req)
            .await
            .map_err(UpstreamFailure::from_client)
    }
}

fn read_certs(pem: &[u8]) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, GfeError> {
    let mut reader = std::io::BufReader::new(pem);
    let mut out = Vec::new();
    for item in rustls_pemfile::certs(&mut reader) {
        out.push(item.map_err(|e| GfeError::Tls(format!("parsing certs: {e}")))?);
    }
    Ok(out)
}

fn read_key(pem: &[u8]) -> Result<rustls::pki_types::PrivateKeyDer<'static>, GfeError> {
    let mut reader = std::io::BufReader::new(pem);
    match rustls_pemfile::private_key(&mut reader) {
        Ok(Some(key)) => Ok(key),
        Ok(None) => Err(GfeError::Tls("no private key in PEM".into())),
        Err(e) => Err(GfeError::Tls(format!("parsing key: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::failure::FailureKind;

    #[test]
    fn builds_client() {
        // Construction must succeed (validates the ring provider + roots wiring).
        assert!(UpstreamClient::new(32).is_ok());
    }

    #[test]
    fn builds_client_with_mtls() {
        let cert = rcgen::generate_simple_self_signed(vec!["client.local".into()]).unwrap();
        let opts = UpstreamClientOptions {
            idle_per_host: 8,
            client_cert_pem: Some(cert.cert.pem().into_bytes()),
            client_key_pem: Some(cert.key_pair.serialize_pem().into_bytes()),
            extra_ca_pem: Some(cert.cert.pem().into_bytes()),
            ..Default::default()
        };
        assert!(UpstreamClient::with_options(opts).is_ok());
    }

    /// A backend that never answers the TCP handshake must fail within the
    /// connect timeout, not the operating system's (minutes-long) default.
    #[tokio::test]
    async fn gives_up_connecting_after_connect_timeout() {
        use http_body_util::{BodyExt, Empty};
        use std::time::{Duration, Instant};

        let client = UpstreamClient::with_options(UpstreamClientOptions {
            connect_timeout: Some(Duration::from_millis(200)),
            ..Default::default()
        })
        .unwrap();
        let req = Request::builder()
            .uri("/")
            .body(
                Empty::<Bytes>::new()
                    .map_err(|e| Box::new(e) as BoxError)
                    .boxed(),
            )
            .unwrap();

        // TEST-NET-1 (RFC 5737) is never routed, so the SYN goes unanswered.
        let start = Instant::now();
        let result = client.send(Scheme::Http, "192.0.2.1:80", req).await;

        let failure = result.expect_err("an unroutable backend cannot answer");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
        // Without a route to TEST-NET-1 at all, the connect fails at once.
        assert!(
            matches!(
                failure.kind,
                FailureKind::ConnectTimeout | FailureKind::ConnectError
            ),
            "{failure}"
        );
    }

    #[tokio::test]
    async fn reports_a_closed_port_as_connect_refused() {
        use http_body_util::{BodyExt, Empty};

        // Bind and drop: the port is free, so connecting to it is refused.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let authority = closed.local_addr().unwrap().to_string();
        drop(closed);
        let client = UpstreamClient::new(1).unwrap();
        let req = Request::builder()
            .uri("/")
            .body(
                Empty::<Bytes>::new()
                    .map_err(|e| Box::new(e) as BoxError)
                    .boxed(),
            )
            .unwrap();

        let failure = client
            .send(Scheme::Http, &authority, req)
            .await
            .err()
            .unwrap();

        assert_eq!(failure.kind, FailureKind::ConnectRefused, "{failure}");
    }

    /// A local HTTP/1.1 server that answers every request after `delay`.
    async fn spawn_slow_server(delay: Duration) -> String {
        use http_body_util::Empty;
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let svc = service_fn(move |_req| async move {
                        tokio::time::sleep(delay).await;
                        Ok::<_, std::convert::Infallible>(Response::new(Empty::<Bytes>::new()))
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        authority
    }

    fn get() -> Request<ReqBody> {
        use http_body_util::{BodyExt, Empty};
        Request::builder()
            .uri("/")
            .body(
                Empty::<Bytes>::new()
                    .map_err(|e| Box::new(e) as BoxError)
                    .boxed(),
            )
            .unwrap()
    }

    /// The backend is reached at its own address whatever the request's
    /// target: `*` must not run into the backend's port.
    #[tokio::test]
    async fn reaches_the_backend_whatever_the_request_target() {
        let backend = spawn_slow_server(Duration::ZERO).await;
        let client = UpstreamClient::new(1).unwrap();
        let mut req = get();
        *req.method_mut() = hyper::Method::OPTIONS;
        *req.uri_mut() = hyper::Uri::from_static("*");

        let result = client.send(Scheme::Http, &backend, req).await;

        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[tokio::test]
    async fn refuses_to_open_more_connections_than_the_limit() {
        let backend = spawn_slow_server(Duration::from_millis(300)).await;
        let client = UpstreamClient::with_options(UpstreamClientOptions {
            max_connections: Some(1),
            ..Default::default()
        })
        .unwrap();

        // The first request occupies the only connection there may be.
        let busy = {
            let (client, backend) = (client.clone(), backend.clone());
            tokio::spawn(async move { client.send(Scheme::Http, &backend, get()).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        let refused = client.send(Scheme::Http, &backend, get()).await;

        let failure = refused.expect_err("a second connection exceeds the limit");
        assert_eq!(failure.kind, FailureKind::ConnectionLimit, "{failure}");
        assert!(busy.await.unwrap().is_ok());
    }

    /// A connection left idle is closed once `idle_timeout` has passed, even
    /// if nothing is ever sent to its backend again.
    #[tokio::test]
    async fn closes_a_connection_idle_for_idle_timeout() {
        use http_body_util::BodyExt;

        let backend = spawn_slow_server(Duration::ZERO).await;
        let client = UpstreamClient::with_options(UpstreamClientOptions {
            idle_timeout: Some(Duration::from_millis(200)),
            ..Default::default()
        })
        .unwrap();
        let response = client.send(Scheme::Http, &backend, get()).await.unwrap();
        response.into_body().collect().await.unwrap();
        assert_eq!(client.open_connections(), 1);

        let mut open = client.open_connections();
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            open = client.open_connections();
            if open == 0 {
                break;
            }
        }

        assert_eq!(open, 0);
    }

    #[tokio::test]
    async fn reuses_a_pooled_connection_at_the_limit() {
        let backend = spawn_slow_server(Duration::ZERO).await;
        let client = UpstreamClient::with_options(UpstreamClientOptions {
            idle_per_host: 1,
            max_connections: Some(1),
            ..Default::default()
        })
        .unwrap();

        let first = client.send(Scheme::Http, &backend, get()).await;
        let second = client.send(Scheme::Http, &backend, get()).await;

        assert!(first.is_ok() && second.is_ok());
        assert_eq!(client.open_connections(), 1);
        assert_eq!(client.max_connections(), Some(1));
    }

    /// A backend that completes the HTTP/2 handshake, takes a request and
    /// then goes silent without closing the connection, as a host that lost
    /// power does.
    async fn spawn_backend_dying_after_the_request() -> String {
        use http_body_util::Empty;
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let request_seen = Arc::new(tokio::sync::Notify::new());
            let svc = service_fn({
                let request_seen = request_seen.clone();
                move |_req| {
                    request_seen.notify_one();
                    std::future::pending::<Result<Response<Empty<Bytes>>, std::convert::Infallible>>(
                    )
                }
            });
            let conn = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), svc);
            tokio::pin!(conn);
            tokio::select! {
                _ = &mut conn => {}
                _ = request_seen.notified() => {}
            }
            // Stop driving the connection but keep its socket open: pings
            // go unanswered and nothing tells the client.
            std::future::pending::<()>().await;
        });
        authority
    }

    #[tokio::test]
    async fn notices_a_dead_http2_backend_through_keep_alive() {
        let backend = spawn_backend_dying_after_the_request().await;
        let client = UpstreamClient::with_options(UpstreamClientOptions {
            http2_keep_alive: Some(KeepAlive {
                idle: Duration::from_millis(100),
                timeout: Duration::from_millis(100),
            }),
            ..Default::default()
        })
        .unwrap();

        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            client.send(Scheme::H2c, &backend, get()),
        )
        .await;

        let failure = outcome
            .expect("the dead connection should be noticed")
            .expect_err("a dead backend cannot answer");
        assert_eq!(failure.kind, FailureKind::Reset, "{failure}");
    }
}
