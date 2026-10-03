//! Health probes: TCP connect, HTTP GET, HTTPS GET, gRPC health check.

use async_trait::async_trait;
use bytes::Bytes;
use gfe_types::{HealthCheckConfig, ProbeType, Scheme};
use http_body_util::{BodyExt, Empty, Full};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

/// Outcome of a single probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    /// Backend responded as expected.
    Pass,
    /// Backend signalled lame-duck drain (configured `drain_status`).
    Drain,
    /// Backend failed the probe.
    Fail,
}

/// A health probe against a backend.
#[async_trait]
pub trait Probe: Send + Sync {
    async fn check(&self, host: &str, port: u16, timeout: Duration) -> ProbeResult;
}

/// Build a probe from a health-check config, for a backend of a pool with
/// the given `scheme`.
pub fn make_probe(cfg: &HealthCheckConfig, scheme: Scheme) -> Box<dyn Probe> {
    match cfg.probe_type {
        ProbeType::Tcp => Box::new(TcpProbe),
        // A gRPC server is reached the way the pool's traffic reaches it.
        ProbeType::Grpc => Box::new(GrpcProbe {
            tls: scheme == Scheme::Https,
        }),
        // `http` is the node default, so it is what an `https` pool without
        // its own check gets: probing its TLS port in cleartext would fail
        // every backend.
        ProbeType::Http => Box::new(HttpProbe {
            path: cfg.path.clone(),
            expected: cfg.expected_status,
            drain: cfg.drain_status,
            tls: scheme == Scheme::Https,
        }),
        ProbeType::Https => Box::new(HttpProbe {
            path: cfg.path.clone(),
            expected: cfg.expected_status,
            drain: cfg.drain_status,
            tls: true,
        }),
    }
}

/// TCP connect probe: success = connection established.
pub struct TcpProbe;

#[async_trait]
impl Probe for TcpProbe {
    async fn check(&self, host: &str, port: u16, timeout: Duration) -> ProbeResult {
        match tokio::time::timeout(timeout, TcpStream::connect((host, port))).await {
            Ok(Ok(_)) => ProbeResult::Pass,
            _ => ProbeResult::Fail,
        }
    }
}

/// HTTP(S) GET probe: `Pass` when status equals `expected`, `Drain` when it
/// equals the configured `drain` status, else `Fail`.
pub struct HttpProbe {
    path: String,
    expected: u16,
    drain: Option<u16>,
    tls: bool,
}

#[async_trait]
impl Probe for HttpProbe {
    async fn check(&self, host: &str, port: u16, timeout: Duration) -> ProbeResult {
        let fut = async {
            let stream = TcpStream::connect((host, port)).await.ok()?;
            if self.tls {
                self.check_tls(stream, host).await
            } else {
                self.check_plain(stream, host).await
            }
        };
        match tokio::time::timeout(timeout, fut).await {
            Ok(Some(status)) if status == self.expected => ProbeResult::Pass,
            Ok(Some(status)) if Some(status) == self.drain => ProbeResult::Drain,
            _ => ProbeResult::Fail,
        }
    }
}

impl HttpProbe {
    async fn check_plain(&self, stream: TcpStream, host: &str) -> Option<u16> {
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.ok()?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        self.send(&mut sender, host).await
    }

    async fn check_tls(&self, stream: TcpStream, host: &str) -> Option<u16> {
        let connector = tokio_rustls::TlsConnector::from(health_tls_config());
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).ok()?;
        let tls = connector.connect(server_name, stream).await.ok()?;
        let io = TokioIo::new(tls);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.ok()?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        self.send(&mut sender, host).await
    }

    /// Send the probe request and return the response status code.
    async fn send(
        &self,
        sender: &mut hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
        host: &str,
    ) -> Option<u16> {
        let req = Request::builder()
            .uri(&self.path)
            .header("host", host)
            .header("user-agent", "gfe-health/0.1")
            .body(Empty::<Bytes>::new())
            .ok()?;
        let resp = sender.send_request(req).await.ok()?;
        Some(resp.status().as_u16())
    }
}

/// What a gRPC server reports about itself (`grpc.health.v1.ServingStatus`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServingStatus {
    Serving,
    /// The server asks not to be sent traffic, typically while shutting down.
    NotServing,
    /// `UNKNOWN`, `SERVICE_UNKNOWN`, or a value this probe does not know.
    Other,
}

/// Read the serving status out of the body of a `Check` response: one gRPC
/// frame (a 1-byte compression flag and a 4-byte length) holding a
/// `HealthCheckResponse`, whose only field is the status.
fn serving_status(body: &[u8]) -> Option<ServingStatus> {
    let (header, rest) = body.split_at_checked(5)?;
    if header[0] != 0 {
        // Compressed; the probe did not offer any compression.
        return None;
    }
    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    match rest.get(..length)? {
        // Field 1, varint.
        [0x08, 1, ..] => Some(ServingStatus::Serving),
        [0x08, 2, ..] => Some(ServingStatus::NotServing),
        // An empty message is the default value, UNKNOWN.
        _ => Some(ServingStatus::Other),
    }
}

/// The request of a `Check` call: one gRPC frame holding an empty
/// `HealthCheckRequest`, which asks about the server as a whole.
const CHECK_REQUEST: &[u8] = &[0, 0, 0, 0, 0];

/// gRPC health probe: calls `grpc.health.v1.Health/Check`. `Pass` when the
/// server reports `SERVING`; `Drain` when it reports `NOT_SERVING`, which is
/// how a gRPC server announces it is going away; `Fail` otherwise, including
/// when it does not implement the health service.
pub struct GrpcProbe {
    tls: bool,
}

#[async_trait]
impl Probe for GrpcProbe {
    async fn check(&self, host: &str, port: u16, timeout: Duration) -> ProbeResult {
        match tokio::time::timeout(timeout, self.call(host, port)).await {
            Ok(Some(ServingStatus::Serving)) => ProbeResult::Pass,
            Ok(Some(ServingStatus::NotServing)) => ProbeResult::Drain,
            _ => ProbeResult::Fail,
        }
    }
}

impl GrpcProbe {
    async fn call(&self, host: &str, port: u16) -> Option<ServingStatus> {
        let stream = TcpStream::connect((host, port)).await.ok()?;
        let authority = format!("{host}:{port}");
        if self.tls {
            let connector = tokio_rustls::TlsConnector::from(health_tls_config_http2());
            let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).ok()?;
            let tls = connector.connect(server_name, stream).await.ok()?;
            Self::check_over(TokioIo::new(tls), "https", &authority).await
        } else {
            Self::check_over(TokioIo::new(stream), "http", &authority).await
        }
    }

    /// Run the `Check` call over an established connection (HTTP/2 with
    /// prior knowledge, as gRPC requires).
    async fn check_over<I>(io: I, scheme: &str, authority: &str) -> Option<ServingStatus>
    where
        I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    {
        let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .ok()?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method("POST")
            .uri(format!(
                "{scheme}://{authority}/grpc.health.v1.Health/Check"
            ))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("user-agent", "gfe-health/0.1")
            .body(Full::new(Bytes::from_static(CHECK_REQUEST)))
            .ok()?;
        let resp = sender.send_request(req).await.ok()?;
        if resp.status() != hyper::StatusCode::OK {
            return None;
        }
        // The call's own status is in the trailers, or in the headers when
        // the server fails it without sending a message.
        let failed_early = resp.headers().contains_key("grpc-status");
        let response = resp.into_body().collect().await.ok()?;
        let call_ok = response
            .trailers()
            .and_then(|trailers| trailers.get("grpc-status"))
            .is_some_and(|status| status == "0");
        if failed_early || !call_ok {
            return None;
        }
        serving_status(&response.to_bytes())
    }
}

/// [`health_tls_config`] offering HTTP/2, which a gRPC server requires.
fn health_tls_config_http2() -> Arc<rustls::ClientConfig> {
    use std::sync::OnceLock;
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut cfg = (*health_tls_config()).clone();
            cfg.alpn_protocols = vec![b"h2".to_vec()];
            Arc::new(cfg)
        })
        .clone()
}

/// A rustls client config for HTTPS health probes that does **not** verify the
/// server certificate. Health checks are a liveness signal, not a security
/// boundary, and backends commonly present internal/self-signed certs. This is
/// intentionally separate from the upstream *traffic* client, which validates
/// certs against the trust store.
fn health_tls_config() -> Arc<rustls::ClientConfig> {
    use std::sync::OnceLock;
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let cfg = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("tls versions")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth();
            Arc::new(cfg)
        })
        .clone()
}

/// Accept-any certificate verifier (health probes only — see [`health_tls_config`]).
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tcp_probe_detects_closed_port() {
        // Port 1 on loopback is virtually always closed/refused quickly.
        let probe = TcpProbe;
        assert_eq!(
            probe
                .check("127.0.0.1", 1, Duration::from_millis(200))
                .await,
            ProbeResult::Fail
        );
    }

    #[tokio::test]
    async fn tcp_probe_detects_open_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let probe = TcpProbe;
        assert_eq!(
            probe
                .check("127.0.0.1", addr.port(), Duration::from_millis(500))
                .await,
            ProbeResult::Pass
        );
    }

    #[test]
    fn reads_the_serving_status_from_a_check_response() {
        assert_eq!(
            serving_status(&[0, 0, 0, 0, 2, 0x08, 1]),
            Some(ServingStatus::Serving)
        );
        assert_eq!(
            serving_status(&[0, 0, 0, 0, 2, 0x08, 2]),
            Some(ServingStatus::NotServing)
        );
    }

    #[test]
    fn an_empty_check_response_is_not_serving_status() {
        // An empty message is the protobuf default: UNKNOWN.
        assert_eq!(serving_status(&[0, 0, 0, 0, 0]), Some(ServingStatus::Other));
    }

    #[test]
    fn a_truncated_check_response_has_no_status() {
        assert_eq!(serving_status(&[]), None);
        assert_eq!(serving_status(&[0, 0, 0, 0, 2, 0x08]), None);
    }

    /// A cleartext HTTP/2 server speaking the gRPC health-checking protocol.
    /// It reports `status` (a `ServingStatus` value), or, given `None`,
    /// fails the call as a server without a health service does.
    async fn spawn_grpc_health(status: Option<u8>) -> u16 {
        use hyper::service::service_fn;
        use std::convert::Infallible;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| async move {
                        assert_eq!(req.uri().path(), "/grpc.health.v1.Health/Check");
                        let (message, call_status) = match status {
                            Some(status) => (vec![0, 0, 0, 0, 2, 0x08, status], "0"),
                            None => (Vec::new(), "12"),
                        };
                        let mut trailers = hyper::HeaderMap::new();
                        trailers.insert("grpc-status", call_status.parse().unwrap());
                        let body = Full::new(Bytes::from(message))
                            .with_trailers(async move { Some(Ok::<_, Infallible>(trailers)) });
                        let resp = hyper::Response::builder()
                            .header("content-type", "application/grpc")
                            .body(body)
                            .unwrap();
                        Ok::<_, Infallible>(resp)
                    });
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        port
    }

    async fn grpc_check(port: u16) -> ProbeResult {
        GrpcProbe { tls: false }
            .check("127.0.0.1", port, Duration::from_secs(2))
            .await
    }

    #[tokio::test]
    async fn grpc_probe_passes_a_serving_backend() {
        let port = spawn_grpc_health(Some(1)).await;
        assert_eq!(grpc_check(port).await, ProbeResult::Pass);
    }

    #[tokio::test]
    async fn grpc_probe_drains_a_backend_that_is_not_serving() {
        let port = spawn_grpc_health(Some(2)).await;
        assert_eq!(grpc_check(port).await, ProbeResult::Drain);
    }

    #[tokio::test]
    async fn grpc_probe_fails_a_backend_without_a_health_service() {
        let port = spawn_grpc_health(None).await;
        assert_eq!(grpc_check(port).await, ProbeResult::Fail);
    }

    #[tokio::test]
    async fn grpc_probe_fails_a_backend_that_is_down() {
        assert_eq!(grpc_check(1).await, ProbeResult::Fail);
    }

    /// Spawn an HTTP/1.1 server over TLS (self-signed) answering 200 to
    /// everything, and return its port.
    async fn spawn_tls_healthz() -> u16 {
        use hyper::service::service_fn;
        use std::convert::Infallible;

        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(generated.key_pair.serialize_der().into());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![generated.cert.der().clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let svc = service_fn(|_req| async {
                        Ok::<_, Infallible>(hyper::Response::new(Full::new(Bytes::from("ok"))))
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
                });
            }
        });
        port
    }

    /// The node default probe type is `http`: a pool of scheme `https`
    /// inheriting it must be probed the way its traffic reaches it.
    #[tokio::test]
    async fn http_probe_uses_tls_for_an_https_pool() {
        let port = spawn_tls_healthz().await;
        let probe = make_probe(&HealthCheckConfig::default(), Scheme::Https);

        let result = probe.check("127.0.0.1", port, Duration::from_secs(2)).await;

        assert_eq!(result, ProbeResult::Pass);
    }

    #[tokio::test]
    async fn http_probe_stays_cleartext_for_an_http_pool() {
        let port = spawn_tls_healthz().await;
        let probe = make_probe(&HealthCheckConfig::default(), Scheme::Http);

        let result = probe.check("127.0.0.1", port, Duration::from_secs(2)).await;

        assert_eq!(result, ProbeResult::Fail);
    }
}
