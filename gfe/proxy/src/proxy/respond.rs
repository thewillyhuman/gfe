//! The answers GFE writes itself: a route's fixed response or redirect, and
//! the small, consistent answer to a request it cannot serve, in gRPC's
//! terms for a gRPC call.
//!
//! Every answer carries the request's `X-Request-Id`, so that a client can
//! quote it, and none says more than what went wrong in a few words: no
//! internals leak.

use crate::proxy::failure::FailureKind;
use bytes::Bytes;
use http::StatusCode;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
use pingora_core::protocols::http::HttpTask;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;

/// Why GFE answers a request itself instead of relaying a backend's answer.
/// Each says how it is answered and what the access log's `error` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The request target's authority and `Host` disagree.
    HostConflict,
    /// Nothing names the host.
    HostMissing,
    /// The host is not covered by the certificate of the connection's SNI.
    Misdirected,
    /// The request head is larger than `max_header_bytes`.
    HeaderTooLarge,
    /// No route matches.
    NoRoute,
    /// The target of a forwarded request is not a path (`OPTIONS *`,
    /// `CONNECT`).
    UnsupportedTarget,
    /// The request asks for a protocol upgrade, which GFE does not relay.
    UpgradeNotSupported,
    /// The route forwards to a pool the config does not have.
    PoolNotFound,
    /// The pool has `max_in_flight` requests in flight.
    PoolFull,
    /// The pool has no backend that may receive requests.
    NoHealthyUpstream,
    /// The client stopped sending the request body.
    RequestBodyTimeout,
    /// The backend failed before responding.
    Upstream(FailureKind),
}

impl Refusal {
    /// The HTTP status GFE answers with.
    pub(crate) fn status(self) -> StatusCode {
        match self {
            Refusal::HostConflict | Refusal::HostMissing | Refusal::UnsupportedTarget => {
                StatusCode::BAD_REQUEST
            }
            Refusal::Misdirected => StatusCode::MISDIRECTED_REQUEST,
            Refusal::HeaderTooLarge => StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            Refusal::NoRoute => StatusCode::NOT_FOUND,
            Refusal::UpgradeNotSupported => StatusCode::NOT_IMPLEMENTED,
            Refusal::PoolNotFound => StatusCode::BAD_GATEWAY,
            Refusal::PoolFull | Refusal::NoHealthyUpstream => StatusCode::SERVICE_UNAVAILABLE,
            Refusal::RequestBodyTimeout => StatusCode::REQUEST_TIMEOUT,
            Refusal::Upstream(FailureKind::ConnectionLimit) => StatusCode::SERVICE_UNAVAILABLE,
            Refusal::Upstream(FailureKind::Timeout) => StatusCode::GATEWAY_TIMEOUT,
            Refusal::Upstream(_) => StatusCode::BAD_GATEWAY,
        }
    }

    /// The access log's `error`.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Refusal::HostConflict => "host_conflict",
            Refusal::HostMissing => "host_missing",
            Refusal::Misdirected => "misdirected_request",
            Refusal::HeaderTooLarge => "request_header_too_large",
            Refusal::NoRoute => "no_route",
            Refusal::UnsupportedTarget => "unsupported_request_target",
            Refusal::UpgradeNotSupported => "upgrade_not_supported",
            Refusal::PoolNotFound => "pool_not_found",
            Refusal::PoolFull => "upstream_pool_full",
            Refusal::NoHealthyUpstream => "no_healthy_upstream",
            Refusal::RequestBodyTimeout => "request_body_timeout",
            Refusal::Upstream(kind) => kind.reason(),
        }
    }

    /// The few words the answer says.
    pub(crate) fn message(self) -> &'static str {
        match self {
            Refusal::HostConflict => "conflicting host",
            Refusal::HostMissing => "missing host",
            Refusal::Misdirected => "misdirected request",
            Refusal::HeaderTooLarge => "request header too large",
            Refusal::NoRoute => "no route",
            Refusal::UnsupportedTarget => "unsupported request target",
            Refusal::UpgradeNotSupported => "protocol upgrade not supported",
            Refusal::PoolNotFound => "pool not found",
            Refusal::PoolFull => "upstream pool full",
            Refusal::NoHealthyUpstream => "no healthy upstream",
            Refusal::RequestBodyTimeout => "request body timeout",
            Refusal::Upstream(FailureKind::ConnectionLimit) => "upstream connection limit",
            Refusal::Upstream(FailureKind::Timeout) => "upstream timeout",
            Refusal::Upstream(_) => "upstream error",
        }
    }
}

/// A response GFE writes itself: its head and its whole body.
#[derive(Debug)]
pub(crate) struct Answer {
    pub(crate) header: ResponseHeader,
    pub(crate) body: Bytes,
}

impl Answer {
    /// The answer's status.
    pub(crate) fn status(&self) -> u16 {
        self.header.status.as_u16()
    }

    /// The gRPC status the answer carries, if it is a gRPC failure.
    pub(crate) fn grpc_status(&self) -> Option<u8> {
        self.header
            .headers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
    }
}

/// How GFE answers a request it refuses: a compact `text/plain` answer, or,
/// to a gRPC call, a gRPC failure carrying the same reason. A gRPC client
/// reads a call's outcome from `grpc-status`, not from the HTTP status.
pub(crate) fn refusal(refusal: Refusal, request_id: &str, grpc: bool) -> Answer {
    if grpc {
        let message = format!("gfe: {}", refusal.reason());
        grpc_failure(
            GrpcCode::for_http_status(refusal.status()),
            &message,
            request_id,
        )
    } else {
        synthetic(refusal.status(), refusal.message(), request_id)
    }
}

/// A compact `text/plain` answer carrying the request id for correlation.
pub(crate) fn synthetic(status: StatusCode, message: &str, request_id: &str) -> Answer {
    let body = Bytes::from(format!(
        "{} {}\nrequest-id: {}\n",
        status.as_u16(),
        message,
        request_id
    ));
    let mut header = head(status, request_id, body.len());
    insert(
        &mut header,
        CONTENT_TYPE.as_str(),
        "text/plain; charset=utf-8",
    );
    Answer { header, body }
}

/// The gRPC status codes GFE answers with when it fails a call itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrpcCode {
    Unknown = 2,
    PermissionDenied = 7,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    Unauthenticated = 16,
}

impl GrpcCode {
    /// The gRPC status a client derives from an HTTP status when a response
    /// carries no `grpc-status` of its own (gRPC's HTTP-to-gRPC status
    /// mapping). Answering with it directly tells clients the same thing,
    /// without relying on each of them to implement the fallback.
    pub(crate) fn for_http_status(status: StatusCode) -> GrpcCode {
        match status.as_u16() {
            400 => GrpcCode::Internal,
            401 => GrpcCode::Unauthenticated,
            403 => GrpcCode::PermissionDenied,
            404 => GrpcCode::Unimplemented,
            429 | 502 | 503 | 504 => GrpcCode::Unavailable,
            _ => GrpcCode::Unknown,
        }
    }
}

/// A gRPC "trailers-only" response: an HTTP 200 with no body whose headers
/// carry the call's status. This is how a call is failed before any message
/// has been sent. `message` must be printable ASCII without `%`.
pub(crate) fn grpc_failure(code: GrpcCode, message: &str, request_id: &str) -> Answer {
    let mut header = head(StatusCode::OK, request_id, 0);
    insert(&mut header, CONTENT_TYPE.as_str(), "application/grpc");
    insert(&mut header, "grpc-status", &(code as u16).to_string());
    insert(&mut header, "grpc-message", message);
    Answer {
        header,
        body: Bytes::new(),
    }
}

/// A redirect to the same host and path under `scheme` (e.g. HTTP→HTTPS).
/// A status that is not a valid HTTP status redirects with `308`.
pub(crate) fn redirect(
    scheme: &str,
    status: u16,
    host: &str,
    path_and_query: &str,
    request_id: &str,
) -> Answer {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::PERMANENT_REDIRECT);
    let mut header = head(status, request_id, 0);
    insert(
        &mut header,
        LOCATION.as_str(),
        &format!("{scheme}://{host}{path_and_query}"),
    );
    Answer {
        header,
        body: Bytes::new(),
    }
}

/// A route's fixed answer. A status that is not a valid HTTP status
/// answers `200`.
pub(crate) fn fixed(status: u16, body: &str, request_id: &str) -> Answer {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    let body = Bytes::copy_from_slice(body.as_bytes());
    Answer {
        header: head(status, request_id, body.len()),
        body,
    }
}

/// Write `answer` to the client, in full.
pub(crate) async fn send(session: &mut Session, answer: Answer) -> pingora_error::Result<()> {
    let Answer { header, body } = answer;
    let mut tasks = Vec::with_capacity(2);
    let ends_with_head = body.is_empty();
    tasks.push(HttpTask::Header(Box::new(header), ends_with_head));
    if !ends_with_head {
        tasks.push(HttpTask::Body(Some(body), true));
    }
    session.write_response_tasks(tasks).await.map(|_| ())
}

/// The head every answer starts with: its status, its length and the
/// request id.
fn head(status: StatusCode, request_id: &str, content_length: usize) -> ResponseHeader {
    let mut header = ResponseHeader::build(status, Some(4))
        .expect("a valid status code always builds a response head");
    insert(
        &mut header,
        CONTENT_LENGTH.as_str(),
        &content_length.to_string(),
    );
    insert(&mut header, "x-request-id", request_id);
    header
}

/// Set a header, leaving it out if `value` cannot be a header value: a
/// request id is the client's, and an answer is better than none.
fn insert(header: &mut ResponseHeader, name: &'static str, value: &str) {
    if let Ok(value) = http::HeaderValue::from_str(value) {
        header
            .insert_header(name, value)
            .expect("a static header name is always valid");
    }
}

#[cfg(test)]
#[path = "respond_test.rs"]
mod tests;
