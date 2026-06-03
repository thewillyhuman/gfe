//! Health probes: TCP connect, HTTP GET, HTTPS GET.

use async_trait::async_trait;
use bytes::Bytes;
use gfe_types::{HealthCheckConfig, ProbeType};
use http_body_util::Empty;
use hyper::Request;
use hyper_util::rt::TokioIo;
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

/// Build a probe from a health-check config.
pub fn make_probe(cfg: &HealthCheckConfig) -> Box<dyn Probe> {
    match cfg.probe_type {
        ProbeType::Tcp => Box::new(TcpProbe),
        ProbeType::Http => Box::new(HttpProbe {
            path: cfg.path.clone(),
            expected: cfg.expected_status,
            drain: cfg.drain_status,
            tls: false,
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
}
