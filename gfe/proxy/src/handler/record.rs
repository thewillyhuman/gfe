//! Per-request accounting: everything GFE knows about one request, reported
//! exactly once, as metrics and as a `gfe::access` event, when the exchange
//! is over.
//!
//! "Over" means the response body was written to its last byte, or the
//! exchange was abandoned. A [`RequestRecord`] reports itself when dropped,
//! so whoever holds it decides when that is: the handler while the response
//! is being produced, then the response body ([`RequestRecord::respond`]).
//! A request whose handler is cancelled, because the client went away
//! before any response, is therefore still reported, as abandoned, with
//! what had been transferred.
//!
//! The record decides nothing about the request; it is told what happened.

use crate::edge::ConnInfo;
use crate::handler::request;
use crate::handler::respond::GRPC_STATUS;
use crate::metrics::{AbortLabels, GfeMetrics, GrpcLabels, RequestLabels, RouteLabels};
use crate::routing::CompiledRoute;
use netkit_http::body::{Body, BoxBody, BoxError, Frame, SizeHint};
use netkit_http::header::USER_AGENT;
use netkit_http::{Bytes, HeaderMap, Method, Request, Response, Version};
use std::any::Any;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

/// Logged as the status of a request the client abandoned before GFE had a
/// response for it. Not a real HTTP status: the convention nginx established.
const CLIENT_CLOSED_REQUEST: u16 = 499;

/// The highest status code gRPC defines (`UNAUTHENTICATED`). Anything above
/// it is not reported, which keeps the metric label bounded.
const MAX_GRPC_STATUS: u8 = 16;

/// Label value for requests that matched no route.
const NO_ROUTE: &str = "none";

/// The `grpc-status` in a set of response headers or trailers, if valid.
pub(crate) fn grpc_status(headers: &HeaderMap) -> Option<u8> {
    let status: u8 = headers.get(GRPC_STATUS)?.to_str().ok()?.parse().ok()?;
    (status <= MAX_GRPC_STATUS).then_some(status)
}

/// A duration in milliseconds, to the microsecond.
pub(crate) fn millis(duration: Duration) -> f64 {
    duration.as_micros() as f64 / 1000.0
}

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

    /// The `by` label of `gfe_requests_aborted_total`, if it was aborted.
    fn aborted_by(self) -> Option<&'static str> {
        match self {
            Termination::Complete => None,
            Termination::ClientAbort => Some("client"),
            Termination::UpstreamAbort => Some("upstream"),
        }
    }
}

/// The upstream leg of a forwarded request.
struct UpstreamLeg {
    pool: String,
    /// The backend of the last attempt, if one was selected.
    backend: Option<String>,
    attempts: u32,
    /// Time from the first attempt until the response head arrived.
    time_to_first_byte: Option<Duration>,
    /// Whatever marks the backend as busy with this request. Held until the
    /// response ends, the attempt fails, or the next attempt replaces it.
    busy: Option<Box<dyn Any + Send + Sync>>,
}

/// One request, from its parsed head to the end of its exchange.
pub(crate) struct RequestRecord {
    metrics: Arc<GfeMetrics>,
    started: Instant,
    conn: Arc<ConnInfo>,
    /// The id of the listener it arrived on, as configured when it did.
    listener: String,
    request_id: String,
    method: Method,
    http_version: Version,
    /// The host the request is for, as used for routing.
    host: String,
    path: String,
    user_agent: Option<String>,
    is_grpc: bool,
    route: Option<Arc<CompiledRoute>>,
    upstream: Option<UpstreamLeg>,
    /// The status of the response; `None` while there is none.
    status: Option<u16>,
    /// Why GFE answered the request itself instead of relaying a response.
    error: Option<&'static str>,
    /// The status a gRPC call ended with. It arrives in the trailers, or in
    /// the headers when the call fails before sending any message.
    grpc_status: Option<u8>,
    request_bytes: Arc<AtomicU64>,
    response_bytes: u64,
    termination: Termination,
}

impl RequestRecord {
    /// Start accounting for `request`, which arrived on `conn` for `host`
    /// and is known as `request_id`, counting it in `metrics` as in flight.
    pub(crate) fn begin<B>(
        metrics: Arc<GfeMetrics>,
        conn: Arc<ConnInfo>,
        request: &Request<B>,
        host: String,
        request_id: String,
    ) -> Self {
        metrics.proxy.requests_in_flight.inc();
        let headers = request.headers();
        RequestRecord {
            metrics,
            started: Instant::now(),
            listener: conn.listener().id.0.clone(),
            conn,
            request_id,
            method: request.method().clone(),
            http_version: request.version(),
            host,
            path: request.uri().path().to_string(),
            user_agent: headers
                .get(USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            is_grpc: request::is_grpc(headers),
            route: None,
            upstream: None,
            status: None,
            error: None,
            grpc_status: None,
            request_bytes: Arc::new(AtomicU64::new(0)),
            response_bytes: 0,
            // Until a response body says otherwise, the only way the record
            // can end is the client abandoning the request.
            termination: Termination::ClientAbort,
        }
    }

    /// The request's id.
    pub(crate) fn request_id(&self) -> &str {
        &self.request_id
    }

    /// The host the request is for, as used for routing.
    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    /// Whether the request is a gRPC call.
    pub(crate) fn is_grpc(&self) -> bool {
        self.is_grpc
    }

    /// The request matched `route`.
    pub(crate) fn matched(&mut self, route: Arc<CompiledRoute>) {
        self.route = Some(route);
    }

    /// GFE is answering the request itself, because of `reason` (the access
    /// log's `error`). A backend the request was being sent to is done with
    /// it.
    pub(crate) fn failed(&mut self, reason: &'static str) {
        self.error = Some(reason);
        if let Some(upstream) = &mut self.upstream {
            upstream.busy = None;
        }
    }

    /// The request is being forwarded to `pool`.
    pub(crate) fn forwarding_to(&mut self, pool: String) {
        self.upstream = Some(UpstreamLeg {
            pool,
            backend: None,
            attempts: 0,
            time_to_first_byte: None,
            busy: None,
        });
    }

    /// An attempt is being made against `backend`. `busy` is dropped when
    /// the backend is done with the request: when the response ends, the
    /// attempt fails, or another attempt is made.
    pub(crate) fn attempting(&mut self, backend: String, busy: impl Any + Send + Sync) {
        if let Some(upstream) = &mut self.upstream {
            upstream.backend = Some(backend);
            upstream.attempts += 1;
            upstream.busy = Some(Box::new(busy));
        }
    }

    /// The backend answered with a response head, `elapsed` after the first
    /// attempt started.
    pub(crate) fn upstream_responded(&mut self, elapsed: Duration) {
        if let Some(upstream) = &mut self.upstream {
            upstream.time_to_first_byte = Some(elapsed);
        }
    }

    /// The counter the request body's bytes are added to as they are read.
    pub(crate) fn request_bytes(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.request_bytes)
    }

    /// Hand the record over to `response`: it is reported when the response
    /// body has been written out or abandoned.
    pub(crate) fn respond(mut self, response: Response<BoxBody>) -> Response<BoxBody> {
        self.status = Some(response.status().as_u16());
        if self.is_grpc {
            self.grpc_status = grpc_status(response.headers());
        }
        response.map(|inner| {
            let mut observed = ObservedBody {
                inner,
                record: self,
            };
            observed.note_if_ended();
            netkit_http::body::boxed(observed)
        })
    }

    /// Report the request: the single place a request is counted and
    /// logged.
    fn report(&self) {
        let metrics = &self.metrics.proxy;
        let elapsed = self.started.elapsed();
        let status = self.status.unwrap_or(CLIENT_CLOSED_REQUEST);
        let request_bytes = self.request_bytes.load(Ordering::Relaxed);
        let (route, vhost) = match &self.route {
            Some(route) => (route.id.0.as_str(), route.host.as_str()),
            None => (NO_ROUTE, NO_ROUTE),
        };
        let per_route = RouteLabels {
            listener: self.listener.clone(),
            vhost: vhost.to_string(),
            route: route.to_string(),
        };

        metrics.requests_in_flight.dec();
        metrics
            .requests
            .get_or_create(&RequestLabels {
                listener: per_route.listener.clone(),
                vhost: per_route.vhost.clone(),
                route: per_route.route.clone(),
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
        if let Some(grpc_status) = self.grpc_status {
            metrics
                .grpc_responses
                .get_or_create(&GrpcLabels {
                    listener: per_route.listener.clone(),
                    vhost: per_route.vhost.clone(),
                    route: per_route.route.clone(),
                    grpc_status: grpc_status.to_string(),
                })
                .inc();
        }
        if let Some(by) = self.termination.aborted_by() {
            metrics
                .requests_aborted
                .get_or_create(&AbortLabels {
                    listener: per_route.listener.clone(),
                    vhost: per_route.vhost.clone(),
                    route: per_route.route.clone(),
                    by: by.to_string(),
                })
                .inc();
        }

        // One structured event per request, under a distinct target so
        // operators can route or sample it independently.
        let upstream = self.upstream.as_ref();
        let client = self.conn.client();
        let tls = self.conn.tls();
        tracing::info!(
            target: "gfe::access",
            request_id = %self.request_id,
            client = %client.ip(),
            client_port = client.port(),
            listener = %self.listener,
            proto = if tls.is_some() { "https" } else { "http" },
            http_version = ?self.http_version,
            sni = self.conn.sni(),
            tls_version = tls.map(|tls| tls.version),
            tls_cipher = tls.map(|tls| tls.cipher.as_str()),
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

impl Drop for RequestRecord {
    fn drop(&mut self) {
        self.report();
    }
}

impl std::fmt::Debug for RequestRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestRecord")
            .field("request_id", &self.request_id)
            .field("host", &self.host)
            .field("path", &self.path)
            .field("status", &self.status)
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// A response body that carries its request's record to the end of the
/// exchange, counting the bytes written and noting how the body ended.
struct ObservedBody {
    inner: BoxBody,
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
                    this.record.response_bytes += data.len() as u64;
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

#[cfg(test)]
#[path = "record_test.rs"]
mod tests;
