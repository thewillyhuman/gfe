//! The answers GFE writes itself: a route's fixed response or redirect, and
//! the small, consistent answer to a request it cannot serve, in gRPC's
//! terms for a gRPC call.
//!
//! Every answer carries the request's `X-Request-Id`, so that a client can
//! quote it, and none says more than what went wrong in a few words: no
//! internals leak. Deciding when to answer, and accounting for the answer,
//! is the caller's.

use crate::handler::failure::FailureKind;
use crate::handler::request::X_REQUEST_ID;
use netkit_http::body::{self, BoxBody};
use netkit_http::header::{CONTENT_TYPE, LOCATION, RETRY_AFTER};
use netkit_http::{HeaderName, HeaderValue, Response, StatusCode};

/// The headers a gRPC "trailers-only" failure carries.
pub(crate) const GRPC_STATUS: HeaderName = HeaderName::from_static("grpc-status");
const GRPC_MESSAGE: HeaderName = HeaderName::from_static("grpc-message");

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
    /// The pool has admitted `max_requests_per_second` requests within the
    /// last second.
    PoolRateLimited,
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
            // Tells a client that reused a connection to retry on a new one.
            Refusal::Misdirected => StatusCode::MISDIRECTED_REQUEST,
            Refusal::NoRoute => StatusCode::NOT_FOUND,
            Refusal::UpgradeNotSupported => StatusCode::NOT_IMPLEMENTED,
            Refusal::PoolNotFound => StatusCode::BAD_GATEWAY,
            Refusal::PoolFull | Refusal::NoHealthyUpstream => StatusCode::SERVICE_UNAVAILABLE,
            Refusal::PoolRateLimited => StatusCode::TOO_MANY_REQUESTS,
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
            Refusal::NoRoute => "no_route",
            Refusal::UnsupportedTarget => "unsupported_request_target",
            Refusal::UpgradeNotSupported => "upgrade_not_supported",
            Refusal::PoolNotFound => "pool_not_found",
            Refusal::PoolFull => "upstream_pool_full",
            Refusal::PoolRateLimited => "upstream_pool_rate_limited",
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
            Refusal::NoRoute => "no route",
            Refusal::UnsupportedTarget => "unsupported request target",
            Refusal::UpgradeNotSupported => "protocol upgrade not supported",
            Refusal::PoolNotFound => "pool not found",
            Refusal::PoolFull => "upstream pool full",
            Refusal::PoolRateLimited => "upstream pool rate limited",
            Refusal::NoHealthyUpstream => "no healthy upstream",
            Refusal::RequestBodyTimeout => "request body timeout",
            Refusal::Upstream(FailureKind::ConnectionLimit) => "upstream connection limit",
            Refusal::Upstream(FailureKind::Timeout) => "upstream timeout",
            Refusal::Upstream(_) => "upstream error",
        }
    }

    /// How many seconds the client should wait before trying again, when
    /// that is known: a pool over its rate admits again within a second.
    fn retry_after(self) -> Option<u32> {
        match self {
            Refusal::PoolRateLimited => Some(1),
            _ => None,
        }
    }
}

/// How GFE answers a request it refuses: a compact `text/plain` answer,
/// saying when to retry where that is known, or, to a gRPC call (`grpc`),
/// a gRPC failure carrying the same reason. A gRPC client reads a call's
/// outcome from `grpc-status`, not from the HTTP status, and backs off on
/// its own.
pub(crate) fn refusal(refusal: Refusal, request_id: &str, grpc: bool) -> Response<BoxBody> {
    if grpc {
        let message = format!("gfe: {}", refusal.reason());
        return grpc_failure(
            GrpcCode::for_http_status(refusal.status()),
            &message,
            request_id,
        );
    }
    let mut response = synthetic(refusal.status(), refusal.message(), request_id);
    if let Some(seconds) = refusal.retry_after() {
        response
            .headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from(seconds));
    }
    response
}

/// A compact `text/plain` answer carrying the request id for correlation.
pub(crate) fn synthetic(status: StatusCode, message: &str, request_id: &str) -> Response<BoxBody> {
    let text = format!(
        "{} {}\nrequest-id: {}\n",
        status.as_u16(),
        message,
        request_id
    );
    let mut response = answer(status, body::full(text), request_id);
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
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
pub(crate) fn grpc_failure(code: GrpcCode, message: &str, request_id: &str) -> Response<BoxBody> {
    let mut response = answer(StatusCode::OK, body::empty(), request_id);
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
    headers.insert(GRPC_STATUS, HeaderValue::from(code as u16));
    if let Ok(message) = HeaderValue::from_str(message) {
        headers.insert(GRPC_MESSAGE, message);
    }
    response
}

/// A redirect to the same host and path under `scheme` (e.g. HTTP to
/// HTTPS). A status that is not a valid HTTP status redirects with `308`.
pub(crate) fn redirect(
    scheme: &str,
    status: u16,
    host: &str,
    path_and_query: &str,
    request_id: &str,
) -> Response<BoxBody> {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::PERMANENT_REDIRECT);
    let mut response = answer(status, body::empty(), request_id);
    if let Ok(location) = HeaderValue::from_str(&format!("{scheme}://{host}{path_and_query}")) {
        response.headers_mut().insert(LOCATION, location);
    }
    response
}

/// A route's fixed answer. A status that is not a valid HTTP status
/// answers `200`.
pub(crate) fn fixed(status: u16, text: &str, request_id: &str) -> Response<BoxBody> {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    answer(status, body::full(text.to_string()), request_id)
}

/// An answer with `status` and `content`, carrying the request id. An id
/// that cannot be a header value is left out: it is the client's, and an
/// answer is better than none.
fn answer(status: StatusCode, content: BoxBody, request_id: &str) -> Response<BoxBody> {
    let mut response = Response::new(content);
    *response.status_mut() = status;
    if let Ok(id) = HeaderValue::from_str(request_id) {
        response.headers_mut().insert(X_REQUEST_ID, id);
    }
    response
}

#[cfg(test)]
#[path = "respond_test.rs"]
mod tests;
