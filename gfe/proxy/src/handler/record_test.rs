use super::*;
use arc_swap::ArcSwap;
use gfe_config::{ListenProtocol, Listener, ListenerId, RouteAction, RouteId};
use netkit_http::HeaderValue;
use netkit_http::body::{self, BodyExt};
use netkit_tls::TlsInfo;
use std::convert::Infallible;
use std::sync::Mutex;

fn headers(grpc_status: &'static str) -> HeaderMap {
    let mut map = HeaderMap::new();
    map.insert("grpc-status", HeaderValue::from_static(grpc_status));
    map
}

#[test]
fn reads_a_defined_grpc_status() {
    assert_eq!(grpc_status(&headers("0")), Some(0));
    assert_eq!(grpc_status(&headers("14")), Some(14));
}

#[test]
fn ignores_missing_or_undefined_grpc_status() {
    assert_eq!(grpc_status(&HeaderMap::new()), None);
    assert_eq!(grpc_status(&headers("17")), None);
    assert_eq!(grpc_status(&headers("ok")), None);
}

#[test]
fn keeps_millisecond_values_to_the_microsecond() {
    assert_eq!(millis(Duration::from_micros(1500)), 1.5);
}

fn conn(tls: Option<TlsInfo>) -> Arc<ConnInfo> {
    let listener = Arc::new(ArcSwap::from_pointee(Listener {
        id: ListenerId("http".into()),
        address: "127.0.0.1".parse().unwrap(),
        port: 80,
        protocol: ListenProtocol::Http,
    }));
    Arc::new(ConnInfo::new(
        "127.0.0.1:5000".parse().unwrap(),
        "127.0.0.1:80".parse().unwrap(),
        listener,
        tls,
    ))
}

fn request(content_type: &'static str) -> Request<()> {
    Request::builder()
        .uri("/path?q=1")
        .header("content-type", content_type)
        .header("user-agent", "test/1")
        .body(())
        .unwrap()
}

fn record_with(
    metrics: &Arc<GfeMetrics>,
    conn: Arc<ConnInfo>,
    content_type: &'static str,
) -> RequestRecord {
    RequestRecord::begin(
        Arc::clone(metrics),
        conn,
        &request(content_type),
        "a.example.org".into(),
        "abc".into(),
    )
}

fn record(metrics: &Arc<GfeMetrics>) -> RequestRecord {
    record_with(metrics, conn(None), "text/plain")
}

fn route() -> Arc<CompiledRoute> {
    Arc::new(CompiledRoute {
        id: RouteId("web".into()),
        host: "*.example.org".into(),
        path_prefix: "/".into(),
        action: RouteAction::Forward("pool".into()),
    })
}

fn exposes(metrics: &GfeMetrics, line: &str) -> bool {
    metrics.encode().contains(line)
}

#[test]
fn counts_a_request_in_flight_until_it_is_reported() {
    let metrics = Arc::new(GfeMetrics::new());

    let record = record(&metrics);
    assert!(exposes(&metrics, "gfe_requests_in_flight 1"));
    drop(record);

    assert!(exposes(&metrics, "gfe_requests_in_flight 0"));
}

#[test]
fn reports_a_request_without_a_response_as_499_by_the_client() {
    let metrics = Arc::new(GfeMetrics::new());

    drop(record(&metrics));

    assert!(exposes(
        &metrics,
        r#"gfe_requests_total{listener="http",vhost="none",route="none",status="499"} 1"#
    ));
    assert!(exposes(
        &metrics,
        r#"gfe_requests_aborted_total{listener="http",vhost="none",route="none",by="client"} 1"#
    ));
}

#[tokio::test]
async fn reports_a_response_read_to_its_end_under_its_route() {
    let metrics = Arc::new(GfeMetrics::new());
    let mut record = record(&metrics);
    record.matched(route());

    let response = record.respond(Response::new(body::full("hello")));
    response.into_body().collect().await.unwrap();

    let labels = r#"listener="http",vhost="*.example.org",route="web""#;
    for expected in [
        format!("gfe_requests_total{{{labels},status=\"200\"}} 1"),
        format!("gfe_response_body_bytes_total{{{labels}}} 5"),
    ] {
        assert!(exposes(&metrics, &expected), "missing {expected}");
    }
    assert!(!exposes(&metrics, "gfe_requests_aborted_total{"));
}

#[tokio::test]
async fn reports_the_request_bytes_counted() {
    let metrics = Arc::new(GfeMetrics::new());
    let record = record(&metrics);
    record.request_bytes().fetch_add(3, Ordering::Relaxed);

    drop(record.respond(Response::new(body::empty())));

    assert!(exposes(
        &metrics,
        r#"gfe_request_body_bytes_total{listener="http",vhost="none",route="none"} 3"#
    ));
}

#[test]
fn reports_a_response_the_client_did_not_read_to_its_end_as_a_client_abort() {
    let metrics = Arc::new(GfeMetrics::new());

    drop(record(&metrics).respond(Response::new(body::full("hello"))));

    assert!(exposes(
        &metrics,
        r#"gfe_requests_total{listener="http",vhost="none",route="none",status="200"} 1"#
    ));
    assert!(exposes(
        &metrics,
        r#"gfe_requests_aborted_total{listener="http",vhost="none",route="none",by="client"} 1"#
    ));
}

/// A body that fails at once, as a backend that dies mid-body does.
struct Broken;

impl Body for Broken {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Poll::Ready(Some(Err(std::io::Error::other("reset"))))
    }
}

#[tokio::test]
async fn reports_a_response_the_backend_broke_off_as_an_upstream_abort() {
    let metrics = Arc::new(GfeMetrics::new());

    let response = record(&metrics).respond(Response::new(body::boxed(Broken)));
    let _ = response.into_body().collect().await;

    assert!(exposes(
        &metrics,
        r#"gfe_requests_aborted_total{listener="http",vhost="none",route="none",by="upstream"} 1"#
    ));
}

#[tokio::test]
async fn reports_the_grpc_status_of_the_trailers() {
    let metrics = Arc::new(GfeMetrics::new());
    let record = record_with(&metrics, conn(None), "application/grpc");
    let content = Frames(
        [
            Frame::data(Bytes::from_static(b"message")),
            Frame::trailers(headers("5")),
        ]
        .into(),
    );

    let response = record.respond(Response::new(body::boxed(content)));
    response.into_body().collect().await.unwrap();

    assert!(exposes(
        &metrics,
        r#"gfe_grpc_responses_total{listener="http",vhost="none",route="none",grpc_status="5"} 1"#
    ));
}

#[test]
fn reports_the_grpc_status_of_a_trailers_only_response() {
    let metrics = Arc::new(GfeMetrics::new());
    let record = record_with(&metrics, conn(None), "application/grpc");
    let mut response = Response::new(body::empty());
    *response.headers_mut() = headers("14");

    drop(record.respond(response));

    assert!(exposes(
        &metrics,
        r#"gfe_grpc_responses_total{listener="http",vhost="none",route="none",grpc_status="14"} 1"#
    ));
}

#[test]
fn gives_the_backend_back_when_gfe_answers_itself() {
    let metrics = Arc::new(GfeMetrics::new());
    let busy = Arc::new(());
    let mut record = record(&metrics);
    record.forwarding_to("pool".into());
    record.attempting("10.0.0.1:80".into(), Arc::clone(&busy));

    record.failed("upstream_error");

    assert_eq!(Arc::strong_count(&busy), 1);
}

/// A body of the frames given, all ready at once.
struct Frames(std::collections::VecDeque<Frame<Bytes>>);

impl Body for Frames {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Poll::Ready(self.0.pop_front().map(Ok))
    }
}

/// The `gfe::access` event `report` emits, as JSON fields.
fn access_event(report: impl FnOnce()) -> serde_json::Value {
    #[derive(Clone, Default)]
    struct Lines(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Lines {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let lines = Lines::default();
    let writer = lines.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, report);
    let raw = lines.0.lock().unwrap().clone();
    let line: serde_json::Value = serde_json::from_slice(raw.trim_ascii()).unwrap();
    assert_eq!(line["target"], "gfe::access");
    line["fields"].clone()
}

#[test]
fn access_event_describes_the_request() {
    let metrics = Arc::new(GfeMetrics::new());
    let tls = TlsInfo {
        sni: Some("a.example.org".into()),
        version: "TLSv1.3",
        cipher: "TLS13_AES_256_GCM_SHA384".into(),
        alpn: Some("h2".into()),
        resumed: false,
    };
    let mut record = record_with(&metrics, conn(Some(tls)), "text/plain");
    record.matched(route());
    record.forwarding_to("pool".into());
    record.attempting("10.0.0.1:80".into(), ());
    record.upstream_responded(Duration::from_micros(1500));

    let event = access_event(|| drop(record.respond(Response::new(body::empty()))));

    assert_eq!(event["request_id"], "abc");
    assert_eq!(event["client"], "127.0.0.1");
    assert_eq!(event["client_port"], 5000);
    assert_eq!(event["listener"], "http");
    assert_eq!(event["proto"], "https");
    assert_eq!(event["sni"], "a.example.org");
    assert_eq!(event["tls_version"], "TLSv1.3");
    assert_eq!(event["method"], "GET");
    assert_eq!(event["host"], "a.example.org");
    assert_eq!(event["path"], "/path");
    assert_eq!(event["user_agent"], "test/1");
    assert_eq!(event["status"], 200);
    assert_eq!(event["route"], "web");
    assert_eq!(event["pool"], "pool");
    assert_eq!(event["backend"], "10.0.0.1:80");
    assert_eq!(event["attempts"], 1);
    assert_eq!(event["termination"], "complete");
    assert_eq!(event["upstream_ttfb_ms"], 1.5);
    assert!(event.get("error").is_none());
}

#[test]
fn access_event_says_why_gfe_answered_itself() {
    let metrics = Arc::new(GfeMetrics::new());
    let mut record = record(&metrics);
    record.failed("no_route");

    let event = access_event(|| drop(record));

    assert_eq!(event["error"], "no_route");
    assert_eq!(event["status"], 499);
    assert_eq!(event["termination"], "client_abort");
    assert_eq!(event["route"], "none");
}
