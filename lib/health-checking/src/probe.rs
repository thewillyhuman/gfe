//! Health probes: TCP connect, HTTP GET, HTTPS GET, gRPC health check.
//!
//! The HTTP and gRPC probes go through Pingora's HTTP connector, the same
//! machinery the proxy uses to reach backends, but never through its
//! connection pools: every probe opens a new connection (TCP, and TLS when
//! the probe uses it) and closes it when done. A probe thereby also proves
//! that the backend still accepts connections, which a reused connection
//! would hide.
//!
//! Every probe is bounded as a whole (name resolution, connect, TLS,
//! request and response) by the timeout it is given; Pingora's own
//! timeouts are left unset.

use async_trait::async_trait;
use bytes::Bytes;
use gfe_config::{HealthCheckConfig, ProbeType, Scheme};
use pingora_core::connectors::http::Connector;
use pingora_core::protocols::ALPN;
use pingora_core::protocols::http::client::HttpSession;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, ErrorType, OkOrErr, OrErr, Result};
use pingora_http::RequestHeader;
use std::fmt::Display;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::OnceLock;
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
    /// Probe the backend at `host:port` (`host` a name or an IP literal,
    /// IPv6 without brackets), giving up after `timeout`.
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
    /// `Host` header is the configured host, without the port.
    async fn status(&self, host: &str, port: u16) -> Result<u16> {
        let peer = new_peer(host, port, self.tls, ALPN::H1).await?;
        let (mut session, _) = connector().get_http_session(&peer).await?;
        let mut request = RequestHeader::build("GET", self.path.as_bytes(), None)?;
        request.insert_header("Host", host)?;
        request.insert_header("User-Agent", USER_AGENT)?;
        session.write_request_header(Box::new(request)).await?;
        session.finish_request_body().await?;
        session.read_response_header().await?;
        let response = session
            .response_header()
            .expect("a response header was just read");
        Ok(response.status.as_u16())
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
    /// prior knowledge in cleartext, as gRPC requires.
    async fn call(&self, host: &str, port: u16) -> Result<ServingStatus> {
        let peer = new_peer(host, port, self.tls, ALPN::H2).await?;
        let (session, _) = connector().get_http_session(&peer).await?;
        let HttpSession::H2(mut session) = session else {
            return Error::e_explain(ErrorType::H2Error, "the backend did not negotiate HTTP/2");
        };
        // `:scheme` and `:authority` come from the URI.
        let uri = http::Uri::builder()
            .scheme(if self.tls { "https" } else { "http" })
            .authority(authority(host, port))
            .path_and_query(CHECK_PATH)
            .build()
            .or_err(ErrorType::InvalidHTTPHeader, "building the Check URI")?;
        let mut request = RequestHeader::build_no_case("POST", CHECK_PATH.as_bytes(), None)?;
        request.set_uri(uri);
        request.insert_header("content-type", "application/grpc")?;
        request.insert_header("te", "trailers")?;
        request.insert_header("user-agent", USER_AGENT)?;
        session.write_request_header(Box::new(request), false)?;
        session
            .write_request_body(Bytes::from_static(CHECK_REQUEST), true)
            .await?;

        session.read_response_header().await?;
        let response = session
            .response_header()
            .expect("a response header was just read");
        if response.status != http::StatusCode::OK {
            return Error::e_explain(
                ErrorType::HTTPStatus(response.status.as_u16()),
                "the Check call was not answered 200",
            );
        }
        // The call's own status is in the trailers, or in the headers when
        // the server fails it without sending a message.
        if let Some(status) = response.headers.get("grpc-status") {
            return Error::e_explain(
                ErrorType::Custom("gRPC call failed"),
                format!("grpc-status {status:?}"),
            );
        }
        let mut body = Vec::new();
        while let Some(chunk) = session.read_response_body().await? {
            body.extend_from_slice(&chunk);
        }
        let trailers = session.read_trailers().await?;
        let call_status = trailers.as_ref().and_then(|t| t.get("grpc-status"));
        if call_status.is_none_or(|status| status != "0") {
            return Error::e_explain(
                ErrorType::Custom("gRPC call failed"),
                format!("grpc-status {call_status:?}"),
            );
        }
        serving_status(&body).or_err(
            ErrorType::Custom("gRPC call failed"),
            "the response is not a HealthCheckResponse",
        )
    }
}

/// `host:port` as a URI authority: an IPv6 literal is bracketed.
fn authority(host: &str, port: u16) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The peer a probe connects to: the first address `host` resolves to, with
/// `host` as SNI.
///
/// Probes do **not** verify the server certificate. Health checks are a
/// liveness signal, not a security boundary, and backends commonly present
/// internal/self-signed certs. This is intentionally separate from the
/// upstream *traffic* connections, which validate certs against the trust
/// store.
async fn new_peer(host: &str, port: u16, tls: bool, alpn: ALPN) -> Result<HttpPeer> {
    let address = first_address(host, port).await?;
    let mut peer = HttpPeer::new(address, tls, host.to_string());
    peer.options.verify_cert = false;
    peer.options.verify_hostname = false;
    peer.options.alpn = alpn;
    // One stream per HTTP/2 connection, so that Pingora never offers a
    // probe's connection to another one.
    peer.options.max_h2_streams = 1;
    Ok(peer)
}

/// The first address `host` resolves to (an IP literal resolves to itself).
async fn first_address(host: &str, port: u16) -> Result<SocketAddr> {
    tokio::net::lookup_host((host, port))
        .await
        .or_err_with(ErrorType::ConnectNoRoute, || format!("resolving {host}"))?
        .next()
        .or_err_with(ErrorType::ConnectNoRoute, || {
            format!("{host} resolves to no address")
        })
}

/// The connector every HTTP and gRPC probe goes through. It is built once:
/// building it reads the system trust store. Probes never hand a session
/// back to it, so its connection pools stay empty and every probe connects
/// anew.
///
/// Building it also installs rustls' process-wide crypto provider (`ring`)
/// when none is installed, which is what lets a probe run in a process
/// where nothing else has.
fn connector() -> &'static Connector {
    static CONNECTOR: OnceLock<Connector> = OnceLock::new();
    CONNECTOR.get_or_init(|| Connector::new(None))
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
