//! Synthetic responses and body helpers.

use bytes::Bytes;
use gfe_core::upstream::BoxError;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::{Response, StatusCode};

pub use gfe_core::server::RespBody;

/// Box a `Full<Bytes>` (infallible) into the unified body type.
pub fn full_body(bytes: Bytes) -> RespBody {
    Full::new(bytes)
        .map_err(|e| Box::new(e) as BoxError)
        .boxed()
}

/// Box an upstream `Incoming` body into the unified body type.
pub fn incoming_body(body: Incoming) -> RespBody {
    body.map_err(|e| Box::new(e) as BoxError).boxed()
}

/// A compact `text/plain` response carrying a request id for correlation.
pub fn synthetic(status: StatusCode, message: &str, request_id: &str) -> Response<RespBody> {
    let body = format!(
        "{} {}\nrequest-id: {}\n",
        status.as_u16(),
        message,
        request_id
    );
    let mut resp = Response::new(full_body(Bytes::from(body)));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    if let Ok(v) = HeaderValue::from_str(request_id) {
        resp.headers_mut().insert("x-request-id", v);
    }
    resp
}

/// The gRPC status codes GFE answers with when it fails a call itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcCode {
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
    pub fn for_http_status(status: StatusCode) -> GrpcCode {
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
pub fn grpc_failure(code: GrpcCode, message: &str, request_id: &str) -> Response<RespBody> {
    let mut resp = Response::new(full_body(Bytes::new()));
    let headers = resp.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
    headers.insert("grpc-status", HeaderValue::from(code as u16));
    for (name, value) in [("grpc-message", message), ("x-request-id", request_id)] {
        if let Ok(value) = HeaderValue::from_str(value) {
            headers.insert(name, value);
        }
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use hyper::body::Body;

    #[test]
    fn gateway_failures_are_unavailable_to_grpc() {
        for status in [502, 503, 504] {
            let status = StatusCode::from_u16(status).unwrap();
            assert_eq!(GrpcCode::for_http_status(status), GrpcCode::Unavailable);
        }
    }

    #[test]
    fn unrouted_calls_are_unimplemented_to_grpc() {
        assert_eq!(
            GrpcCode::for_http_status(StatusCode::NOT_FOUND),
            GrpcCode::Unimplemented
        );
    }

    #[test]
    fn grpc_failure_is_a_trailers_only_response() {
        let resp = grpc_failure(GrpcCode::Unavailable, "gfe: no_healthy_upstream", "abc123");

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["content-type"], "application/grpc");
        assert_eq!(resp.headers()["grpc-status"], "14");
        assert_eq!(resp.headers()["grpc-message"], "gfe: no_healthy_upstream");
        assert_eq!(resp.headers()["x-request-id"], "abc123");
        assert!(resp.body().is_end_stream());
    }

    #[tokio::test]
    async fn synthetic_has_status_and_id() {
        let resp = synthetic(StatusCode::NOT_FOUND, "no route", "abc123");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(resp.headers()["x-request-id"], "abc123");
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(text.contains("404 no route"));
        assert!(text.contains("abc123"));
    }
}
