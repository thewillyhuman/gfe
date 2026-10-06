//! What the unit tests of the edge share: certificates and TLS on both
//! ends, a handler that tells what it was given, raw HTTP/1.1 clients, and
//! the capture of the connection log.

use crate::edge::{ConnInfo, RequestHandler, Shared};
use crate::metrics::GfeMetrics;
use gfe_config::{LimitsConfig, ListenProtocol, Listener, ListenerId, TimeoutsConfig};
use netkit_http::body::{BoxBody, Incoming, full};
use netkit_http::{Request, Response};
use netkit_tls::{Acceptor, CertSpec, CertStore, MinVersion, SniResolver};
use rustls::pki_types::CertificateDer;
use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once, PoisonError};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsConnector;

/// The name the test certificates are issued for.
pub(crate) const NAME: &str = "a.example.org";

/// A self-signed certificate for `name`, written to its own scratch
/// directory and served as the default certificate.
pub(crate) struct TestCert {
    pub(crate) der: CertificateDer<'static>,
    pub(crate) entry: CertSpec,
}

impl TestCert {
    pub(crate) fn new(name: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let cert = rcgen::generate_simple_self_signed(vec![name.to_string()])
            .expect("rcgen signs a valid name");
        let dir = std::env::temp_dir().join(format!(
            "gfe-proxy-edge-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("the temp dir is writable");
        let entry = CertSpec {
            sni: vec![name.to_string()],
            default: true,
            cert_file: dir.join("tls.crt"),
            key_file: dir.join("tls.key"),
        };
        std::fs::write(&entry.cert_file, cert.cert.pem()).expect("the temp dir is writable");
        std::fs::write(&entry.key_file, cert.key_pair.serialize_pem())
            .expect("the temp dir is writable");
        TestCert {
            der: cert.cert.der().clone(),
            entry,
        }
    }
}

/// The acceptor serving `certs`, and its resolver.
pub(crate) fn acceptor(certs: &[&TestCert]) -> (Acceptor, Arc<SniResolver>) {
    let entries: Vec<CertSpec> = certs.iter().map(|cert| cert.entry.clone()).collect();
    let resolver = Arc::new(SniResolver::new(
        CertStore::build(&entries).expect("test certificates load"),
    ));
    let config = netkit_tls::server_config(resolver.clone(), MinVersion::Tls12)
        .expect("the default policy is valid");
    (Acceptor::new(Arc::new(config)), resolver)
}

/// A client trusting `certs`, offering ALPN `alpn`.
pub(crate) fn connector(certs: &[&TestCert], alpn: &[&[u8]]) -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert.der.clone())
            .expect("rcgen certificates parse");
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("the default versions are valid")
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    TlsConnector::from(Arc::new(config))
}

/// Shared state with fresh metrics, default limits and `timeouts`, counting
/// the certificate misses of `resolver`.
pub(crate) fn shared(timeouts: TimeoutsConfig, resolver: Arc<SniResolver>) -> Arc<Shared> {
    shared_with(timeouts, LimitsConfig::default(), resolver)
}

/// [`shared`], held to `limits`.
pub(crate) fn shared_with(
    timeouts: TimeoutsConfig,
    limits: LimitsConfig,
    resolver: Arc<SniResolver>,
) -> Arc<Shared> {
    Arc::new(Shared::new(Arc::new(GfeMetrics::new()), limits, timeouts).with_sni_resolver(resolver))
}

/// A listener `id` on any loopback port, plaintext or TLS.
pub(crate) fn listener(id: &str, protocol: ListenProtocol) -> Listener {
    Listener {
        id: ListenerId(id.into()),
        address: "127.0.0.1".parse().expect("a valid address"),
        port: 0,
        protocol,
    }
}

/// Answers every request with what it was told about it, and keeps the
/// connections it was told about. `/slow/<ms>` takes that long to answer.
#[derive(Default)]
pub(crate) struct Describe {
    seen: Mutex<Vec<Arc<ConnInfo>>>,
    /// Requests being answered right now.
    busy: AtomicUsize,
}

/// Counts a request as being answered until dropped.
struct Busy<'a>(&'a AtomicUsize);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Describe {
    /// The connections of the requests answered so far, in order.
    pub(crate) fn seen(&self) -> Vec<Arc<ConnInfo>> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Wait until `n` requests are being answered.
    pub(crate) async fn until_busy_with(&self, n: usize) {
        eventually(|| self.busy.load(Ordering::SeqCst) == n).await;
    }
}

impl RequestHandler for Describe {
    async fn handle(&self, conn: Arc<ConnInfo>, request: Request<Incoming>) -> Response<BoxBody> {
        self.busy.fetch_add(1, Ordering::SeqCst);
        let _busy = Busy(&self.busy);
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::clone(&conn));
        let path = request.uri().path().to_string();
        if let Some(ms) = path.strip_prefix("/slow/") {
            let ms = ms.parse().expect("a number of milliseconds");
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
        let body = format!(
            "path={path} version={:?} client={} local={} listener={}",
            request.version(),
            conn.client(),
            conn.local(),
            conn.listener().id,
        );
        Response::builder()
            .header("content-length", body.len())
            .body(full(body))
            .expect("a valid response")
    }
}

/// An HTTP/1.1 request for `path` that leaves the connection open.
pub(crate) fn get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nhost: {NAME}\r\n\r\n")
}

/// Whether `received` holds a whole HTTP/1.1 response: its head, and a body
/// of `content-length` bytes.
fn is_complete_response(received: &[u8]) -> bool {
    let text = String::from_utf8_lossy(received);
    let Some(head_end) = text.find("\r\n\r\n") else {
        return false;
    };
    let length = text[..head_end]
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    received.len() >= head_end + 4 + length
}

/// Send `request` and read its response.
pub(crate) async fn exchange<S>(stream: &mut S, request: &str) -> String
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(request.as_bytes())
        .await
        .expect("the request is sent");
    let mut received = Vec::new();
    let mut chunk = [0u8; 4096];
    while !is_complete_response(&received) {
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .expect("a response should arrive")
            .expect("the response is read");
        assert!(read > 0, "closed in the middle of a response: {received:?}");
        received.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8_lossy(&received).into_owned()
}

/// Read until the node closes the connection, at most a few seconds.
pub(crate) async fn read_until_closed<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => received.extend_from_slice(&chunk[..read]),
            }
        }
    })
    .await
    .expect("the node should have closed the connection");
    String::from_utf8_lossy(&received).into_owned()
}

/// The JSON log lines emitted on this thread while the guard is alive.
#[derive(Clone, Default)]
pub(crate) struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

thread_local! {
    static CAPTURING: RefCell<Option<CapturedLogs>> = const { RefCell::new(None) };
}

/// Hands each log line to the test capturing on the thread that emitted it,
/// and drops the lines of threads where no test captures.
struct ToCapturingTest;

impl std::io::Write for ToCapturingTest {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        CAPTURING.with(|capturing| {
            if let Some(logs) = capturing.borrow().as_ref() {
                logs.0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend_from_slice(buf);
            }
        });
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Stops capturing on this thread when dropped.
pub(crate) struct Capturing;

impl Drop for Capturing {
    fn drop(&mut self) {
        CAPTURING.with(|capturing| *capturing.borrow_mut() = None);
    }
}

impl CapturedLogs {
    /// Capture the logs emitted on this thread, as JSON. A `#[tokio::test]`
    /// runs its runtime, and so the connections it serves, on its own
    /// thread. One subscriber serves the whole test binary: `tracing`
    /// caches per callsite whether anybody listens.
    pub(crate) fn start() -> (CapturedLogs, Capturing) {
        static SUBSCRIBER: Once = Once::new();
        SUBSCRIBER.call_once(|| {
            tracing_subscriber::fmt()
                .json()
                .with_writer(|| ToCapturingTest)
                .init();
        });
        let logs = CapturedLogs::default();
        CAPTURING.with(|capturing| *capturing.borrow_mut() = Some(logs.clone()));
        (logs, Capturing)
    }

    /// The fields of the single `gfe::conn` event of the test, waiting for
    /// it to be emitted.
    pub(crate) async fn connection_event(&self) -> serde_json::Value {
        eventually(|| !self.connection_events().is_empty()).await;
        let events = self.connection_events();
        assert_eq!(events.len(), 1, "one connection event: {events:?}");
        events[0].clone()
    }

    /// The fields of every `gfe::conn` event emitted so far.
    pub(crate) fn connection_events(&self) -> Vec<serde_json::Value> {
        let raw = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        String::from_utf8_lossy(&raw)
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|event| event["target"] == "gfe::conn")
            .map(|event| event["fields"].clone())
            .collect()
    }
}

/// Wait for `condition`, looking every few milliseconds, for at most five
/// seconds.
pub(crate) async fn eventually(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "the condition never held");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
