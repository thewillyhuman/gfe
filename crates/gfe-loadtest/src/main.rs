//! `gfe-loadtest` — a self-contained end-to-end load harness for GFE.
//!
//! Two subcommands:
//!   * `upstream` — a fast mock backend returning a fixed body.
//!   * `run`      — a concurrent load client measuring req/s and latency.
//!
//! Not a runtime component; a dev/benchmark tool. See scripts/loadtest.sh.

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use http_body_util::{BodyExt, Empty, Full};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

#[derive(Parser)]
#[command(name = "gfe-loadtest", about = "End-to-end load harness for GFE")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a fast mock upstream returning a fixed body.
    Upstream {
        #[arg(long, default_value = "127.0.0.1:9000")]
        listen: String,
        #[arg(long, default_value_t = 64)]
        body_bytes: usize,
    },
    /// Drive load against a target URL.
    Run {
        #[arg(long)]
        target: String,
        #[arg(long, default_value_t = 64)]
        connections: usize,
        #[arg(long, default_value_t = 8)]
        duration_secs: u64,
        /// `keepalive` (reuse each connection) or `reconnect` (new conn/request).
        #[arg(long, default_value = "keepalive")]
        mode: String,
        /// Label for the printed result row.
        #[arg(long, default_value = "")]
        label: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        match cli.cmd {
            Cmd::Upstream { listen, body_bytes } => run_upstream(&listen, body_bytes).await,
            Cmd::Run {
                target,
                connections,
                duration_secs,
                mode,
                label,
            } => run_load(&target, connections, duration_secs, &mode, &label).await,
        }
    })
}

// ───────────────────────── mock upstream ─────────────────────────

async fn run_upstream(listen: &str, body_bytes: usize) -> Result<()> {
    let body = Bytes::from(vec![b'x'; body_bytes]);
    let listener = TcpListener::bind(listen).await.context("bind upstream")?;
    eprintln!("mock upstream on {listen}, body {body_bytes}B");
    loop {
        let (stream, _) = listener.accept().await?;
        let body = body.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |_req| {
                let body = body.clone();
                async move { Ok::<_, std::convert::Infallible>(Response::new(Full::new(body))) }
            });
            let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await;
        });
    }
}

// ───────────────────────── load client ─────────────────────────

struct Target {
    addr: String,
    host: String,
    path: String,
    tls: bool,
}

fn parse_target(target: &str) -> Result<Target> {
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

async fn run_load(
    target: &str,
    connections: usize,
    duration_secs: u64,
    mode: &str,
    label: &str,
) -> Result<()> {
    let t = Arc::new(parse_target(target)?);
    let reconnect = mode == "reconnect";
    let tls_connector = if t.tls {
        Some(insecure_tls_connector())
    } else {
        None
    };

    let deadline = Instant::now() + Duration::from_secs(duration_secs);
    let started = Instant::now();

    let mut handles = Vec::with_capacity(connections);
    for _ in 0..connections {
        let t = t.clone();
        let connector = tls_connector.clone();
        handles.push(tokio::spawn(async move {
            if reconnect {
                worker_reconnect(t, connector, deadline).await
            } else {
                worker_keepalive(t, connector, deadline).await
            }
        }));
    }

    let mut latencies: Vec<u64> = Vec::new();
    let mut errors: u64 = 0;
    for h in handles {
        let (mut lat, errs) = h.await.unwrap_or((Vec::new(), 1));
        latencies.append(&mut lat);
        errors += errs;
    }
    let elapsed = started.elapsed().as_secs_f64();

    report(label, mode, &mut latencies, errors, elapsed);
    Ok(())
}

/// One connection reused for many sequential requests until the deadline.
async fn worker_keepalive(
    t: Arc<Target>,
    connector: Option<tokio_rustls::TlsConnector>,
    deadline: Instant,
) -> (Vec<u64>, u64) {
    let mut lat = Vec::new();
    let mut errors = 0u64;
    while Instant::now() < deadline {
        let mut sender = match connect_h1(&t, &connector).await {
            Ok(s) => s,
            Err(_) => {
                errors += 1;
                continue;
            }
        };
        while Instant::now() < deadline {
            let start = Instant::now();
            match send_one(&mut sender, &t).await {
                Ok(()) => lat.push(start.elapsed().as_nanos() as u64),
                Err(_) => {
                    errors += 1;
                    break; // reconnect
                }
            }
        }
    }
    (lat, errors)
}

/// A fresh connection (incl. TLS handshake) per request — handshake-bound.
async fn worker_reconnect(
    t: Arc<Target>,
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
            let mut sender = connect_h1(&t, &connector).await?;
            send_one(&mut sender, &t).await
        })
        .await;
        match result {
            Ok(Ok(())) => lat.push(start.elapsed().as_nanos() as u64),
            _ => errors += 1,
        }
    }
    (lat, errors)
}

type Sender = hyper::client::conn::http1::SendRequest<Empty<Bytes>>;

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

async fn send_one(sender: &mut Sender, t: &Target) -> Result<()> {
    let req = Request::builder()
        .uri(&t.path)
        .header("host", &t.host)
        .body(Empty::<Bytes>::new())?;
    let resp = sender.send_request(req).await?;
    if !resp.status().is_success() {
        anyhow::bail!("status {}", resp.status());
    }
    // Drain the body so the connection is reusable.
    let _ = resp.into_body().collect().await?;
    Ok(())
}

fn report(label: &str, mode: &str, latencies: &mut [u64], errors: u64, elapsed: f64) {
    let total = latencies.len() as u64;
    let rps = total as f64 / elapsed;
    latencies.sort_unstable();
    let pct = |p: f64| -> f64 {
        if latencies.is_empty() {
            return 0.0;
        }
        let idx = ((latencies.len() as f64 - 1.0) * p).round() as usize;
        latencies[idx] as f64 / 1000.0 // µs
    };
    println!(
        "{:<38} {:<10} reqs={:<9} {:>10.0} req/s  p50={:>8.1}µs p90={:>8.1}µs p99={:>9.1}µs max={:>9.1}µs errors={}",
        label,
        mode,
        total,
        rps,
        pct(0.50),
        pct(0.90),
        pct(0.99),
        pct(1.0),
        errors
    );
}

// ───────────────────────── TLS (insecure: load tool only) ─────────────────────────

fn insecure_tls_connector() -> tokio_rustls::TlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _e: &rustls::pki_types::CertificateDer<'_>,
        _i: &[rustls::pki_types::CertificateDer<'_>],
        _n: &rustls::pki_types::ServerName<'_>,
        _o: &[u8],
        _t: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
