//! The pooled hyper upstream client. Connection pooling, keep-alive, and
//! h1/h2 are handled by `hyper-util`'s `Client`, keyed per authority; TLS to
//! `https` upstreams is provided by a `hyper-rustls` connector using the
//! `ring` provider and webpki roots.

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
}

/// A cloneable, pooled client for forwarding requests to upstreams.
#[derive(Clone)]
pub struct UpstreamClient {
    client: Client<HttpsConnector<HttpConnector>, ReqBody>,
}

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

        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(http);

        let client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(idle)
            .build(https);

        Ok(UpstreamClient { client })
    }

    /// Forward a request to the given upstream. The request's URI is rebuilt
    /// with `scheme://authority` preserving path and query; the `Host`/
    /// `:authority` is set to the upstream authority.
    pub async fn send(
        &self,
        scheme: Scheme,
        authority: &str,
        mut req: Request<ReqBody>,
    ) -> Result<Response<Incoming>, BoxError> {
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let scheme_str = match scheme {
            Scheme::Http => "http",
            Scheme::Https => "https",
        };
        let uri: hyper::Uri = format!("{scheme_str}://{authority}{path_and_query}").parse()?;
        *req.uri_mut() = uri;

        self.client
            .request(req)
            .await
            .map_err(|e| Box::new(e) as BoxError)
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
        };
        assert!(UpstreamClient::with_options(opts).is_ok());
    }
}
