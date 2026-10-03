//! Per-request accounting: everything GFE knows about one request, reported
//! exactly once, as metrics and as an access-log event, when the exchange is
//! over.
//!
//! "Over" means the response body was written to the last byte, or the
//! exchange was abandoned. A [`RequestRecord`] reports itself when dropped, so
//! whoever holds it decides when that is: the request handler while the
//! response is being produced, then the [`ObservedBody`] wrapped around the
//! response body. A request whose handler is cancelled, because the client
//! went away before any response, is therefore still reported.

use crate::errors::RespBody;
use crate::ConnCtx;
use bytes::{Buf, Bytes};
use gfe_metrics::{AbortLabels, GrpcLabels, RequestLabels, RouteLabels};
use gfe_upstream::BoxError;
use hyper::body::{Body, Frame, SizeHint};
use hyper::{Request, Response, StatusCode};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

/// Logged as the status of a request the client abandoned before GFE had a
/// response for it. Not a real HTTP status: the convention nginx established.
const CLIENT_CLOSED_REQUEST: u16 = 499;

/// The highest status code gRPC defines (`UNAUTHENTICATED`). Anything above
/// it is not reported, which keeps the metric label bounded.
const MAX_GRPC_STATUS: u8 = 16;

/// The `grpc-status` in a set of response headers or trailers, if valid.
fn grpc_status(headers: &http::HeaderMap) -> Option<u8> {
    let status: u8 = headers.get("grpc-status")?.to_str().ok()?.parse().ok()?;
    (status <= MAX_GRPC_STATUS).then_some(status)
}

/// Whether `req` is a gRPC call, going by its content type.
fn is_grpc<B>(req: &Request<B>) -> bool {
    req.headers()
        .get(http::header::CONTENT_TYPE)
        .is_some_and(|value| value.as_bytes().starts_with(b"application/grpc"))
}

/// Label value for requests that matched no route.
const NO_ROUTE: &str = "none";

/// How an exchange ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Termination {
    /// The response was written to the end.
    Complete,
    /// The client went away first: before the response, or in the middle
    /// of it.
    ClientAbort,
    /// The upstream failed in the middle of the response body.
    UpstreamAbort,
}

impl Termination {
    fn as_str(self) -> &'static str {
        match self {
            Termination::Complete => "complete",
            Termination::ClientAbort => "client_abort",
            Termination::UpstreamAbort => "upstream_abort",
        }
    }
}

/// The upstream leg of a forwarded request.
struct UpstreamLeg {
    pool: String,
    /// The backend of the last attempt, if one was selected.
    backend: Option<String>,
    attempts: u32,
    /// Time from the first attempt until response headers arrived.
    time_to_first_byte: Option<Duration>,
}

/// One request, from its parsed head to the end of its exchange.
pub struct RequestRecord {
    ctx: Arc<ConnCtx>,
    started: Instant,
    request_id: String,
    method: http::Method,
    http_version: http::Version,
    host: String,
    path: String,
    user_agent: Option<String>,
    /// The matched route's id and configured host pattern.
    route: Option<(String, String)>,
    upstream: Option<UpstreamLeg>,
    status: Option<StatusCode>,
    /// Why GFE answered the request itself instead of relaying a response.
    error: Option<&'static str>,
    request_bytes: Arc<AtomicU64>,
    response_bytes: u64,
    termination: Termination,
    is_grpc: bool,
    /// The status a gRPC call ended with. It arrives in the trailers, or in
    /// the headers when the call fails before sending any message.
    grpc_status: Option<u8>,
}

impl RequestRecord {
    /// Start accounting for `req`, received on the connection `ctx`.
    pub fn begin<B>(ctx: Arc<ConnCtx>, req: &Request<B>, host: String, request_id: String) -> Self {
        ctx.shared.metrics.proxy.requests_in_flight.inc();
        RequestRecord {
            started: Instant::now(),
            request_id,
            method: req.method().clone(),
            http_version: req.version(),
            host,
            path: req.uri().path().to_string(),
            user_agent: req
                .headers()
                .get(http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
            route: None,
            upstream: None,
            status: None,
            error: None,
            request_bytes: Arc::new(AtomicU64::new(0)),
            response_bytes: 0,
            // Until a response body says otherwise, the only way the record
            // can end is the client abandoning the request.
            termination: Termination::ClientAbort,
            is_grpc: is_grpc(req),
            grpc_status: None,
            ctx,
        }
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// The request's host, as used for routing.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The request matched route `id`, configured for `host_pattern`.
    pub fn matched_route(&mut self, id: String, host_pattern: String) {
        self.route = Some((id, host_pattern));
    }

    /// GFE is answering the request itself, because of `reason`.
    pub fn failed(&mut self, reason: &'static str) {
        self.error = Some(reason);
    }

    /// The request is being forwarded to `pool`.
    pub fn forwarding_to(&mut self, pool: String) {
        self.upstream = Some(UpstreamLeg {
            pool,
            backend: None,
            attempts: 0,
            time_to_first_byte: None,
        });
    }

    /// An attempt is being made against `backend`.
    pub fn attempting(&mut self, backend: String) {
        if let Some(upstream) = &mut self.upstream {
            upstream.backend = Some(backend);
            upstream.attempts += 1;
        }
    }

    /// The upstream answered with response headers, `elapsed` after the
    /// first attempt started.
    pub fn upstream_responded(&mut self, elapsed: Duration) {
        if let Some(upstream) = &mut self.upstream {
            upstream.time_to_first_byte = Some(elapsed);
        }
    }

    /// The counter the request body's bytes are added to as they are read.
    pub fn request_bytes(&self) -> Arc<AtomicU64> {
        self.request_bytes.clone()
    }

    /// Hand the record over to the response: it is reported when the
    /// response body has been written out or abandoned.
    pub fn respond(mut self, resp: Response<RespBody>) -> Response<RespBody> {
        self.status = Some(resp.status());
        if self.is_grpc {
            self.grpc_status = grpc_status(resp.headers());
        }
        resp.map(|body| {
            let mut observed = ObservedBody {
                inner: body,
                record: self,
            };
            observed.note_if_ended();
            RespBody::new(observed)
        })
    }
}

impl Drop for RequestRecord {
    /// Report the request: this is the single place a request is counted
    /// and logged.
    fn drop(&mut self) {
        let metrics = &self.ctx.shared.metrics.proxy;
        let elapsed = self.started.elapsed();
        let status = self
            .status
            .map(|s| s.as_u16())
            .unwrap_or(CLIENT_CLOSED_REQUEST);
        let request_bytes = self.request_bytes.load(Ordering::Relaxed);
        let listener = self.ctx.listener_id.to_string();
        let (route, host_pattern) = match &self.route {
            Some((id, pattern)) => (id.clone(), pattern.clone()),
            None => (NO_ROUTE.to_string(), NO_ROUTE.to_string()),
        };
        let per_route = RouteLabels {
            listener: listener.clone(),
            host: host_pattern.clone(),
            route: route.clone(),
        };

        metrics.requests_in_flight.dec();
        metrics
            .requests
            .get_or_create(&RequestLabels {
                listener: listener.clone(),
                host: host_pattern.clone(),
                route: route.clone(),
                status: status.to_string(),
            })
            .inc();
        metrics
            .request_duration_seconds
            .get_or_create(&per_route)
            .observe(elapsed.as_secs_f64());
        metrics
            .request_body_bytes
            .get_or_create(&per_route)
            .inc_by(request_bytes);
        metrics
            .response_body_bytes
            .get_or_create(&per_route)
            .inc_by(self.response_bytes);
        let aborted_by = match self.termination {
            Termination::Complete => None,
            Termination::ClientAbort => Some("client"),
            Termination::UpstreamAbort => Some("upstream"),
        };
        if let Some(grpc_status) = self.grpc_status {
            metrics
                .grpc_responses
                .get_or_create(&GrpcLabels {
                    listener: listener.clone(),
                    host: host_pattern.clone(),
                    route: route.clone(),
                    grpc_status: grpc_status.to_string(),
                })
                .inc();
        }
        if let Some(by) = aborted_by {
            metrics
                .requests_aborted
                .get_or_create(&AbortLabels {
                    listener,
                    host: host_pattern,
                    route: route.clone(),
                    by: by.to_string(),
                })
                .inc();
        }

        // One structured event per request, under a distinct target so
        // operators can route or sample it independently.
        let upstream = self.upstream.as_ref();
        tracing::info!(
            target: "gfe::access",
            request_id = %self.request_id,
            client = %self.ctx.client_ip,
            client_port = self.ctx.client_port,
            listener = %self.ctx.listener_id,
            proto = if self.ctx.is_tls { "https" } else { "http" },
            http_version = ?self.http_version,
            sni = self.ctx.sni.as_deref(),
            tls_version = self.ctx.tls.as_ref().map(|t| t.version),
            tls_cipher = self.ctx.tls.as_ref().map(|t| t.cipher.as_str()),
            method = %self.method,
            host = %self.host,
            path = %self.path,
            user_agent = self.user_agent.as_deref(),
            status,
            grpc_status = self.grpc_status,
            route = %route,
            pool = upstream.map(|u| u.pool.as_str()),
            backend = upstream.and_then(|u| u.backend.as_deref()),
            attempts = upstream.map(|u| u.attempts),
            error = self.error,
            termination = self.termination.as_str(),
            request_bytes,
            response_bytes = self.response_bytes,
            duration_ms = millis(elapsed),
            upstream_ttfb_ms = upstream.and_then(|u| u.time_to_first_byte).map(millis),
            "request"
        );
    }
}

/// A duration in milliseconds, with microsecond resolution.
pub(crate) fn millis(duration: Duration) -> f64 {
    duration.as_micros() as f64 / 1000.0
}

/// A response body that carries its request's record to the end of the
/// exchange, counting the bytes written and noting how the body ended.
struct ObservedBody {
    inner: RespBody,
    record: RequestRecord,
}

impl ObservedBody {
    /// hyper stops polling a body that reports its own end, so the end has
    /// to be noticed without waiting for a final `None`.
    fn note_if_ended(&mut self) {
        if self.inner.is_end_stream() {
            self.record.termination = Termination::Complete;
        }
    }
}

impl Body for ObservedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        let frame = ready!(Pin::new(&mut this.inner).poll_frame(cx));
        match &frame {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    this.record.response_bytes += data.remaining() as u64;
                }
                if let (true, Some(trailers)) = (this.record.is_grpc, frame.trailers_ref()) {
                    this.record.grpc_status = grpc_status(trailers);
                }
                this.note_if_ended();
            }
            Some(Err(_)) => this.record.termination = Termination::UpstreamAbort,
            None => this.record.termination = Termination::Complete,
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// A request body that adds the bytes read from it to a shared counter.
pub struct CountedBody<B> {
    inner: B,
    bytes: Arc<AtomicU64>,
}

impl<B> CountedBody<B> {
    pub fn new(inner: B, bytes: Arc<AtomicU64>) -> Self {
        CountedBody { inner, bytes }
    }
}

impl<B> Body for CountedBody<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        let this = &mut *self;
        let frame = ready!(Pin::new(&mut this.inner).poll_frame(cx));
        if let Some(Ok(frame)) = &frame {
            if let Some(data) = frame.data_ref() {
                this.bytes
                    .fetch_add(data.remaining() as u64, Ordering::Relaxed);
            }
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(grpc_status: &'static str) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        map.insert("grpc-status", http::HeaderValue::from_static(grpc_status));
        map
    }

    #[test]
    fn reads_a_defined_grpc_status() {
        assert_eq!(grpc_status(&headers("0")), Some(0));
        assert_eq!(grpc_status(&headers("14")), Some(14));
    }

    #[test]
    fn ignores_missing_or_undefined_grpc_status() {
        assert_eq!(grpc_status(&http::HeaderMap::new()), None);
        assert_eq!(grpc_status(&headers("17")), None);
        assert_eq!(grpc_status(&headers("ok")), None);
    }

    #[test]
    fn recognises_grpc_by_content_type() {
        let request = |content_type: &'static str| {
            Request::builder()
                .header("content-type", content_type)
                .body(())
                .unwrap()
        };
        assert!(is_grpc(&request("application/grpc")));
        assert!(is_grpc(&request("application/grpc+proto")));
        assert!(!is_grpc(&request("application/json")));
    }
}
