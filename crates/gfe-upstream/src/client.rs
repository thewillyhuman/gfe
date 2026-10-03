//! The pooled hyper upstream client. Connection pooling, keep-alive, and
//! h1/h2 are handled by `hyper-util`'s `Client`, keyed per authority; TLS to
//! `https` upstreams is provided by a `hyper-rustls` connector using the
//! `ring` provider and webpki roots.
//!
//! The HTTP version on the upstream leg follows the pool's [`Scheme`]:
//! HTTP/1.1 for `http`, whatever ALPN negotiates for `https`, and HTTP/2
//! with prior knowledge for `h2c`. The last one needs a client of its own,
//! as cleartext offers no way to negotiate the version per connection.

use crate::failure::UpstreamFailure;
use crate::limit::{ConnectionLimit, LimitedConnector};
use bytes::Bytes;
use gfe_types::{GfeError, Scheme};
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
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
    /// Client certificate chain (PEM) for mTLS to upstreams.
    pub client_cert_pem: Option<Vec<u8>>,
    /// Client private key (PEM) for mTLS to upstreams.
    pub client_key_pem: Option<Vec<u8>>,
    /// Extra CA bundle (PEM) trusted on top of webpki roots.
    pub extra_ca_pem: Option<Vec<u8>>,
    /// Upper bound on establishing the TCP connection to a backend. `None`
    /// leaves it to the operating system, which can take minutes.
    pub connect_timeout: Option<Duration>,
    /// Upper bound on the upstream connections held open, over all backends.
    /// A request that would need one more fails at once. `None`: no bound.
    pub max_connections: Option<usize>,
}

/// A cloneable, pooled client for forwarding requests to upstreams.
#[derive(Clone)]
pub struct UpstreamClient {
    /// `http` and `https` pools.
    negotiating: Client<Connector, ReqBody>,
    /// `h2c` pools.
    http2_prior_knowledge: Client<Connector, ReqBody>,
    /// Counts, and caps, the connections of both clients together.
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

        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(http);
        let connections = ConnectionLimit::new(opts.max_connections);
        let https = LimitedConnector::new(https, connections.clone());

        let negotiating = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(idle)
            .build(https.clone());
        let http2_prior_knowledge = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(idle)
            .http2_only(true)
            .build(https);

        Ok(UpstreamClient {
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
    /// with `scheme://authority` preserving path and query; the `Host`/
    /// `:authority` is set to the upstream authority.
    pub async fn send(
        &self,
        scheme: Scheme,
        authority: &str,
        mut req: Request<ReqBody>,
    ) -> Result<Response<Incoming>, UpstreamFailure> {
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let (client, uri_scheme) = match scheme {
            Scheme::Http => (&self.negotiating, "http"),
            Scheme::Https => (&self.negotiating, "https"),
            Scheme::H2c => (&self.http2_prior_knowledge, "http"),
        };
        let uri: hyper::Uri = format!("{uri_scheme}://{authority}{path_and_query}")
            .parse()
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
}
