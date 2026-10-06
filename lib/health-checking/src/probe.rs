//! Health probes: TCP connect, HTTP GET, HTTPS GET, gRPC health check.
//!
//! The HTTP and gRPC probes speak through `netkit-http`'s single
//! [`Connection`], never through a pool: every probe opens a new connection
//! (TCP, and TLS when the probe uses it) and closes it when done. A probe
//! thereby also proves that the backend still accepts connections, which a
//! reused connection would hide.
//!
//! Every probe is bounded as a whole (name resolution, connect, TLS,
//! request and response) by the timeout it is given; the connection has no
//! timeout of its own.
//!
//! Probes do not verify the backend's certificate: see `tls_connector`.

use async_trait::async_trait;
use netkit_http::body::{self, BodyExt, BoxError};
use netkit_http::client::{Connection, ConnectionOptions, Protocol};
use netkit_http::{Bytes, Request, StatusCode, header};
use netkit_tls::{Connector, ConnectorOptions, Trust};
use std::fmt::Display;
use std::net::Ipv6Addr;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::net::TcpStream;

/// Outcome of a single probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    /// Backend responded as expected.
    Pass,
    /// Backend signalled lame-duck drain (the probe's drain status, or a gRPC
    /// `NOT_SERVING`).
    Drain,
    /// Backend failed the probe.
    Fail,
}

/// A health probe against a backend.
#[async_trait]
pub trait Probe: Send + Sync {
    /// Probe the backend at `host:port` (`host` a name or an IP literal,
    /// IPv6 without brackets), giving up after `timeout`.
    async fn check(&self, host: &str, port: u16, timeout: Duration) -> ProbeResult;
}

/// What a probe does. Whether it speaks TLS is the caller's to say: it
/// typically probes a backend the way the backend's traffic reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeKind {
    /// A TCP connection can be established.
    Tcp,
    /// `GET path` over HTTP/1.1 answers `expected_status` (pass) or
    /// `drain_status` (drain); any other answer fails.
    Http {
        path: String,
        expected_status: u16,
        drain_status: Option<u16>,
        tls: bool,
    },
    /// The gRPC health-checking protocol (`grpc.health.v1.Health/Check`)
    /// over HTTP/2: negotiated by ALPN with TLS, by prior knowledge without.
    Grpc { tls: bool },
}

/// Build the probe `kind` describes.
pub fn make_probe(kind: &ProbeKind) -> Box<dyn Probe> {
    match kind {
        ProbeKind::Tcp => Box::new(TcpProbe),
        ProbeKind::Http {
            path,
            expected_status,
            drain_status,
            tls,
        } => Box::new(HttpProbe {
            path: path.clone(),
            expected: *expected_status,
            drain: *drain_status,
            tls: *tls,
        }),
        ProbeKind::Grpc { tls } => Box::new(GrpcProbe { tls: *tls }),
    }
}

/// What the probes send as `User-Agent`, so that a backend can tell them
/// from traffic in its logs.
const USER_AGENT: &str = "netkit-health-checking/0.1";

/// TCP connect probe: success = connection established.
pub struct TcpProbe;

#[async_trait]
impl Probe for TcpProbe {
    async fn check(&self, host: &str, port: u16, timeout: Duration) -> ProbeResult {
        match tokio::time::timeout(timeout, TcpStream::connect((host, port))).await {
            Ok(Ok(_)) => ProbeResult::Pass,
            Ok(Err(e)) => failed(host, port, e),
            Err(_) => failed(host, port, "timed out"),
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
        match tokio::time::timeout(timeout, self.status(host, port)).await {
            Ok(Ok(status)) if status == self.expected => ProbeResult::Pass,
            Ok(Ok(status)) if Some(status) == self.drain => ProbeResult::Drain,
            Ok(Ok(status)) => failed(host, port, format_args!("answered {status}")),
            Ok(Err(e)) => failed(host, port, e),
            Err(_) => failed(host, port, "timed out"),
        }
    }
}

impl HttpProbe {
    /// `GET` the path over HTTP/1.1 and return the response status. The
    /// `Host` header is the configured host, without the port. The body is
    /// not read: the connection is closed as soon as the head is in.
    async fn status(&self, host: &str, port: u16) -> Result<u16, BoxError> {
        let mut connection = open(host, port, self.tls, Protocol::Http11).await?;
        let request = Request::get(self.path.as_str())
            .header(header::HOST, host)
            .header(header::USER_AGENT, USER_AGENT)
            .body(body::empty())?;
        let response = connection.send(request).await?;
        Ok(response.status().as_u16())
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

/// The method a `Check` call is a request to.
const CHECK_PATH: &str = "/grpc.health.v1.Health/Check";

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
            Ok(Ok(ServingStatus::Serving)) => ProbeResult::Pass,
            Ok(Ok(ServingStatus::NotServing)) => ProbeResult::Drain,
            Ok(Ok(ServingStatus::Other)) => {
                failed(host, port, "reported neither SERVING nor NOT_SERVING")
            }
            Ok(Err(e)) => failed(host, port, e),
            Err(_) => failed(host, port, "timed out"),
        }
    }
}

impl GrpcProbe {
    /// Run the `Check` call over HTTP/2: negotiated by ALPN over TLS, with
    /// prior knowledge in cleartext, as gRPC requires. `:scheme` and
    /// `:authority` are the connection's.
    async fn call(&self, host: &str, port: u16) -> Result<ServingStatus, BoxError> {
        let mut connection = open(host, port, self.tls, Protocol::Http2).await?;
        let request = Request::post(CHECK_PATH)
            .header(header::CONTENT_TYPE, "application/grpc")
            .header(header::TE, "trailers")
            .header(header::USER_AGENT, USER_AGENT)
            .body(body::full(Bytes::from_static(CHECK_REQUEST)))?;
        let response = connection.send(request).await?;
        if response.status() != StatusCode::OK {
            return Err(format!(
                "the Check call was not answered 200 but {}",
                response.status()
            )
            .into());
        }
        // The call's own status is in the trailers, or in the headers when
        // the server fails it without sending a message.
        if let Some(status) = response.headers().get("grpc-status") {
            return Err(format!("gRPC call failed: grpc-status {status:?}").into());
        }
        let response = response.into_body().collect().await?;
        let call_status = response.trailers().and_then(|t| t.get("grpc-status"));
        if call_status.is_none_or(|status| status != "0") {
            return Err(format!("gRPC call failed: grpc-status {call_status:?}").into());
        }
        serving_status(&response.to_bytes())
            .ok_or_else(|| "gRPC call failed: the response is not a HealthCheckResponse".into())
    }
}

/// A new connection to `host:port` speaking `protocol`, over TLS with `host`
/// as the server name when `tls` is set. It has no connect timeout: the
/// probe's own covers it.
async fn open(
    host: &str,
    port: u16,
    tls: bool,
    protocol: Protocol,
) -> Result<Connection, BoxError> {
    let options = ConnectionOptions {
        protocol,
        tls: tls.then(|| tls_connector().clone()),
        connect_timeout: None,
    };
    Ok(Connection::open(host, port, &options).await?)
}

/// The TLS connector every HTTPS and gRPC-over-TLS probe goes through. It
/// is built once, so that its session cache is shared; every probe still
/// opens a TCP connection and runs a handshake of its own.
///
/// Probes do **not** verify the server certificate. Health checks are a
/// liveness signal, not a security boundary, and backends commonly present
/// internal or self-signed certificates and are often reached by address.
/// This is intentionally separate from the connections that carry traffic,
/// which verify certificates.
fn tls_connector() -> &'static Connector {
    static CONNECTOR: OnceLock<Connector> = OnceLock::new();
    CONNECTOR.get_or_init(|| {
        Connector::new(ConnectorOptions {
            trust: Trust::Unverified,
            identity: None,
        })
        // Only a trust bundle or an identity can be unusable, and there is
        // neither.
        .expect("a connector that verifies nothing and presents nothing")
    })
}

/// `host:port` as a URI authority: an IPv6 literal is bracketed.
fn authority(host: &str, port: u16) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Log why a probe failed, and fail it. At debug level: what operators
/// watch is the committed transition, which the checker logs.
fn failed(host: &str, port: u16, reason: impl Display) -> ProbeResult {
    tracing::debug!(backend = %authority(host, port), %reason, "health probe failed");
    ProbeResult::Fail
}

#[cfg(test)]
#[path = "probe_test.rs"]
mod tests;
