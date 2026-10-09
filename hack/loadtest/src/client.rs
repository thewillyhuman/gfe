//! The load client: connections driven at a target until a deadline,
//! every request timed.

use crate::outcome::Outcome;
use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;

/// Where the requests go, from a URL.
pub struct Target {
    pub addr: String,
    pub host: String,
    pub path: String,
    pub tls: bool,
}

pub fn parse_target(target: &str) -> Result<Target> {
    let uri: hyper::Uri = target.parse().context("parsing target URL")?;
    let scheme = uri.scheme_str().unwrap_or("http");
    let tls = scheme == "https";
    let host = uri.host().context("target has no host")?.to_string();
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let path = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    Ok(Target {
        addr: format!("{host}:{port}"),
        host,
        path,
        tls,
    })
}

/// One scenario: how many connections to drive at a target, for how
/// long, and how they are used.
pub struct Scenario {
    pub target: Arc<Target>,
    pub connections: usize,
    pub duration: Duration,
    /// A new connection per request, instead of one reused until the end.
    pub reconnect: bool,
    /// A new connection per attempt that the server is expected to close
    /// without reading anything, as a node does at a connection limit;
    /// nothing is sent, and the attempt counts as answered when it does.
    pub expect_refusal: bool,
    /// Resume TLS sessions across connections, as a browser does; otherwise
    /// every connection is a full handshake.
    pub resume: bool,
    /// The scenario's name on its row.
    pub label: String,
    /// A process whose CPU per answered request the outcome reports.
    pub cpu_of: Option<u32>,
    /// What each request uploads: empty, and the request is a GET; else
    /// a POST with this body.
    pub upload: Bytes,
    /// Connections opened before the run and held idle through it, each
    /// having carried one request, as the kept connections of clients
    /// that seldom send are: what their presence costs the requests.
    pub idle_connections: usize,
}

impl Scenario {
    /// `keepalive` (reuse each connection), `reconnect` (a new connection
    /// per request) or `refused` (a new connection per attempt, closed by
    /// the server), as the mode is named on the command line and on the
    /// row.
    pub fn mode(&self) -> String {
        if self.expect_refusal {
            return "refused".to_string();
        }
        match (self.reconnect, self.target.tls && !self.resume) {
            (true, true) => "reconnect+full-tls".to_string(),
            (true, false) => "reconnect".to_string(),
            (false, _) => "keepalive".to_string(),
        }
    }
}

/// Drive the scenario's connections until its deadline and measure them.
pub async fn run(scenario: &Scenario) -> Result<Outcome> {
    let connector = scenario
        .target
        .tls
        .then(|| tokio_rustls::TlsConnector::from(crate::tls::client_config(scenario.resume)));
    let idle = hold_idle_connections(scenario, &connector).await?;
    let cpu_before = scenario.cpu_of.map(crate::cpu::cpu_time).transpose()?;
    let deadline = Instant::now() + scenario.duration;
    let started = Instant::now();

    let mut handles = Vec::with_capacity(scenario.connections);
    for _ in 0..scenario.connections {
        let exchange = Exchange {
            target: Arc::clone(&scenario.target),
            upload: scenario.upload.clone(),
        };
        let connector = connector.clone();
        let reconnect = scenario.reconnect;
        let expect_refusal = scenario.expect_refusal;
        handles.push(tokio::spawn(async move {
            if expect_refusal {
                worker_refused(exchange.target, deadline).await
            } else if reconnect {
                worker_reconnect(exchange, connector, deadline).await
            } else {
                worker_keepalive(exchange, connector, deadline).await
            }
        }));
    }

    let mut latencies: Vec<u64> = Vec::new();
    let mut errors: u64 = 0;
    for handle in handles {
        let (mut lat, errs) = handle.await.unwrap_or((Vec::new(), 1));
        latencies.append(&mut lat);
        errors += errs;
    }
    let elapsed = started.elapsed().as_secs_f64();
    drop(idle);

    let mut outcome = Outcome::measure(
        &scenario.label,
        &scenario.mode(),
        &mut latencies,
        errors,
        elapsed,
    );
    outcome.bytes_per_request = scenario.upload.len() as u64;
    if let (Some(pid), Some(before)) = (scenario.cpu_of, cpu_before) {
        outcome.charge_cpu(crate::cpu::cpu_time(pid)?.saturating_sub(before));
    }
    Ok(outcome)
}

/// Open the scenario's idle connections, each having carried one request
/// of the scenario, and keep them open until they are dropped.
async fn hold_idle_connections(
    scenario: &Scenario,
    connector: &Option<tokio_rustls::TlsConnector>,
) -> Result<Vec<Sender>> {
    let exchange = Exchange {
        target: Arc::clone(&scenario.target),
        upload: scenario.upload.clone(),
    };
    let mut held = Vec::with_capacity(scenario.idle_connections);
    for _ in 0..scenario.idle_connections {
        let mut sender = connect_h1(&exchange.target, connector)
            .await
            .with_context(|| format!("opening idle connection {}", held.len() + 1))?;
        send_one(&mut sender, &exchange)
            .await
            .context("the request of an idle connection")?;
        held.push(sender);
    }
    Ok(held)
}

/// What every request of a worker is: where it goes and what it uploads.
#[derive(Clone)]
struct Exchange {
    target: Arc<Target>,
    upload: Bytes,
}

/// One connection reused for many sequential requests until the deadline. A
/// server that says `Connection: close` is obeyed, as an HTTP client would:
/// the next request goes over a new connection, and nothing went wrong.
async fn worker_keepalive(
    exchange: Exchange,
    connector: Option<tokio_rustls::TlsConnector>,
    deadline: Instant,
) -> (Vec<u64>, u64) {
    let mut lat = Vec::new();
    let mut errors = 0u64;
    while Instant::now() < deadline {
        let mut sender = match connect_h1(&exchange.target, &connector).await {
            Ok(s) => s,
            Err(_) => {
                errors += 1;
                continue;
            }
        };
        while Instant::now() < deadline {
            let start = Instant::now();
            match send_one(&mut sender, &exchange).await {
                Ok(reusable) => {
                    lat.push(start.elapsed().as_nanos() as u64);
                    if !reusable {
                        break; // reconnect, as told
                    }
                }
                Err(_) => {
                    errors += 1;
                    break; // reconnect
                }
            }
        }
    }
    (lat, errors)
}

/// A fresh connection (incl. TLS handshake) per request: handshake-bound.
async fn worker_reconnect(
    exchange: Exchange,
    connector: Option<tokio_rustls::TlsConnector>,
    deadline: Instant,
) -> (Vec<u64>, u64) {
    let mut lat = Vec::new();
    let mut errors = 0u64;
    while Instant::now() < deadline {
        let start = Instant::now();
        // Bound each attempt so a stalled connect (e.g. transient loopback
        // port pressure) is counted as a fast error, not a multi-second sample.
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let mut sender = connect_h1(&exchange.target, &connector).await?;
            send_one(&mut sender, &exchange).await
        })
        .await;
        match result {
            Ok(Ok(_)) => lat.push(start.elapsed().as_nanos() as u64),
            _ => errors += 1,
        }
    }
    (lat, errors)
}

/// A fresh TCP connection per attempt, expected to be closed by the server
/// before anything is sent on it: what a node does with a connection over
/// a limit. An attempt counts as answered when the server closes it, and
/// as an error when it cannot be opened or the server sends something
/// instead.
async fn worker_refused(target: Arc<Target>, deadline: Instant) -> (Vec<u64>, u64) {
    let mut lat = Vec::new();
    let mut errors = 0u64;
    while Instant::now() < deadline {
        let start = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(2), closed_unread(&target)).await;
        match result {
            Ok(Ok(())) => lat.push(start.elapsed().as_nanos() as u64),
            _ => errors += 1,
        }
    }
    (lat, errors)
}

/// Connect to the target and wait for the server to close the connection
/// without having been sent anything. A reset counts as a close; a byte
/// from the server does not.
async fn closed_unread(target: &Target) -> Result<()> {
    let mut tcp = TcpStream::connect(&target.addr).await?;
    let mut byte = [0u8; 1];
    match tcp.read(&mut byte).await {
        Ok(0) | Err(_) => Ok(()),
        Ok(_) => anyhow::bail!("the server answered instead of closing"),
    }
}

/// A request's body: none for a GET, the upload for a POST.
type Body = Either<Empty<Bytes>, Full<Bytes>>;

type Sender = hyper::client::conn::http1::SendRequest<Body>;

async fn connect_h1(t: &Target, connector: &Option<tokio_rustls::TlsConnector>) -> Result<Sender> {
    let tcp = TcpStream::connect(&t.addr).await?;
    tcp.set_nodelay(true).ok();
    match connector {
        Some(c) => {
            let name = rustls::pki_types::ServerName::try_from(t.host.clone())?;
            let tls = c.connect(name, tcp).await?;
            h1_handshake(tls).await
        }
        None => h1_handshake(tcp).await,
    }
}

async fn h1_handshake<S>(io: S) -> Result<Sender>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(sender)
}

/// Send one request and read its response. Returns whether the connection
/// may carry another request, which it may not once the server has said
/// `Connection: close`.
async fn send_one(sender: &mut Sender, exchange: &Exchange) -> Result<bool> {
    let target = &exchange.target;
    let req = if exchange.upload.is_empty() {
        Request::get(&target.path)
            .header("host", &target.host)
            .body(Either::Left(Empty::new()))?
    } else {
        Request::post(&target.path)
            .header("host", &target.host)
            .body(Either::Right(Full::new(exchange.upload.clone())))?
    };
    let resp = sender.send_request(req).await?;
    if !resp.status().is_success() {
        anyhow::bail!("status {}", resp.status());
    }
    let told_to_close = resp
        .headers()
        .get(hyper::header::CONNECTION)
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"close"));
    // Drain the body so the connection is reusable.
    let _ = resp.into_body().collect().await?;
    Ok(!told_to_close)
}

#[cfg(test)]
#[path = "client_test.rs"]
mod tests;
