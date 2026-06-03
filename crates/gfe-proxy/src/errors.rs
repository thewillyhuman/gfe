//! Synthetic responses and body helpers.

use bytes::Bytes;
use gfe_upstream::BoxError;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::{Response, StatusCode};

/// The unified response body type the proxy returns to clients.
pub type RespBody = BoxBody<Bytes, BoxError>;

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

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

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
