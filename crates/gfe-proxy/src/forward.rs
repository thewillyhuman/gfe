//! Request/response forwarding: hop-by-hop header hygiene, forwarding
//! headers, the upstream call, and mapping the upstream response back.

use crate::errors::{full_body, incoming_body, synthetic, RespBody};
use crate::progress::SendProgress;
use crate::record::{CountedBody, RequestRecord};
use crate::ConnCtx;
use bytes::Bytes;
use gfe_metrics::{Gauge, PoolLabel, UpstreamDurationLabels, UpstreamErrorLabels, UpstreamLabels};
use gfe_upstream::{BoxError, FailureKind, InflightGuard, Pool};
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http_body_util::BodyExt;
use hyper::body::{Body, Incoming};
use hyper::{Request, Response, StatusCode, Version};
use std::sync::Arc;
use std::time::Instant;

/// Headers that must not be forwarded across a proxy hop (RFC 9110 §7.6.1).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    // Also honor any header names listed in the Connection header.
    let mut named: Vec<HeaderName> = Vec::new();
    if let Some(conn) = headers.get(http::header::CONNECTION) {
        if let Ok(s) = conn.to_str() {
            for tok in s.split(',') {
                if let Ok(name) = HeaderName::from_bytes(tok.trim().as_bytes()) {
                    named.push(name);
                }
            }
        }
    }
    for h in HOP_BY_HOP {
        headers.remove(*h);
    }
    for h in named {
        headers.remove(h);
    }
}

/// Whether the request carries `te: trailers`, and nothing else in `te`.
///
/// `TE` is a hop-by-hop header, but `trailers` is the one value HTTP/2
/// permits (RFC 9113 §8.2.2), and it is not optional for gRPC: clients must
/// send it and servers use it to detect proxies that cannot relay trailers.
fn asks_for_trailers(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(http::header::TE).iter();
    match (values.next(), values.next()) {
        (Some(only), None) => only.as_bytes().eq_ignore_ascii_case(b"trailers"),
        _ => false,
    }
}

fn set_header(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        headers.insert(HeaderName::from_static(name), v);
    }
}

fn append_forwarded_for(headers: &mut HeaderMap, client_ip: &str) {
    let new = match headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        Some(existing) => format!("{existing}, {client_ip}"),
        None => client_ip.to_string(),
    };
    set_header(headers, "x-forwarded-for", &new);
}

/// Make the request's `Host` header the host the client asked for, as
/// HAProxy hands it to backends, whatever protocol the client spoke: the
/// authority of the request target when there is one (always over HTTP/2,
/// where it is `:authority`; an HTTP/1.1 request in absolute form), else
/// the `Host` header as the client sent it, port included.
fn set_requested_host(parts: &mut http::request::Parts) {
    // Any userinfo (`user@`) is not part of the host.
    let target_host = parts.uri.authority().and_then(|authority| {
        let host = authority.as_str().rsplit('@').next().unwrap_or_default();
        HeaderValue::from_str(host).ok()
    });
    if let Some(host) = target_host {
        parts.headers.insert(http::header::HOST, host);
    }
}

/// Whether a request target names a path on the origin server: origin form
/// (`/path`) or absolute form (`http://host/path`). The asterisk form of
/// `OPTIONS *` and the authority form of `CONNECT` do not, and GFE forwards
/// neither.
fn names_a_path(uri: &http::Uri) -> bool {
    uri.path().starts_with('/')
}

/// Idempotent methods that are safe to retry on a pre-response failure.
fn is_idempotent(method: &http::Method) -> bool {
    matches!(
        *method,
        http::Method::GET
            | http::Method::HEAD
            | http::Method::OPTIONS
            | http::Method::TRACE
            | http::Method::DELETE
    )
}

fn empty_body() -> gfe_upstream::ReqBody {
    http_body_util::Empty::<bytes::Bytes>::new()
        .map_err(|e| Box::new(e) as BoxError)
        .boxed()
}

/// Forward a request to a backend selected from `pool`, returning the client
/// response (real or synthetic). Bodyless idempotent requests are retried once
/// against a freshly selected backend on a pre-response failure; everything
/// else is attempted exactly once. GFE never retries after any response bytes
/// have been forwarded.
///
/// The upstream leg (pool, backend, attempts, time to first byte, failure
/// reason) is noted on `record`.
pub async fn forward(
    ctx: &ConnCtx,
    pool: &Arc<Pool>,
    req: Request<Incoming>,
    record: &mut RequestRecord,
) -> Response<RespBody> {
    let shared = &ctx.shared;
    let hash_key = Some(gfe_upstream::policy::hash64(ctx.client_ip));
    let proto = if ctx.is_tls { "https" } else { "http" };
    if !names_a_path(req.uri()) {
        record.failed("unsupported_request_target");
        return synthetic(
            StatusCode::BAD_REQUEST,
            "unsupported request target",
            record.request_id(),
        );
    }
    record.forwarding_to(pool.id.to_string());

    let (mut parts, body) = req.into_parts();
    let asks_for_trailers = asks_for_trailers(&parts.headers);
    strip_hop_by_hop(&mut parts.headers);
    if asks_for_trailers {
        // GFE relays trailers, so it may make this request on its own hop.
        parts
            .headers
            .insert(http::header::TE, HeaderValue::from_static("trailers"));
    }
    append_forwarded_for(&mut parts.headers, &ctx.client_ip.to_string());
    set_header(&mut parts.headers, "x-forwarded-proto", proto);
    set_header(&mut parts.headers, "x-forwarded-host", record.host());
    let forwarded = format!(
        "for={};host={};proto={}",
        ctx.client_ip,
        record.host(),
        proto
    );
    set_header(&mut parts.headers, "forwarded", &forwarded);
    if !parts.headers.contains_key("x-request-id") {
        set_header(&mut parts.headers, "x-request-id", record.request_id());
    }
    set_requested_host(&mut parts);
    // gRPC needs HTTP/2 to the backend; anything else is left to the
    // upstream client.
    let version = if record.is_grpc() {
        Version::HTTP_2
    } else {
        Version::HTTP_11
    };

    // Whether there is a body is decided by the body itself, not by headers:
    // an HTTP/1.1 body may be chunked (and `Transfer-Encoding` is stripped
    // above), and an HTTP/2 body need not announce a `content-length`.
    let retryable = is_idempotent(&parts.method) && body.is_end_stream();
    let max_attempts = if retryable { 2 } else { 1 };
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    // For the non-retryable path we forward the real (streamed) body exactly
    // once, so move it into an Option consumed on the single attempt.
    let forwarding_started = Instant::now();
    let progress = SendProgress::begin(forwarding_started, !retryable);
    let mut streamed_body = if retryable {
        None
    } else {
        let counted = CountedBody::new(body, record.request_bytes(), progress.clone());
        Some(counted.map_err(|e| Box::new(e) as BoxError).boxed())
    };

    for attempt in 0..max_attempts {
        let selection = match pool.select(&shared.health, hash_key) {
            Some(s) => s,
            None => {
                shared.metrics.proxy.no_healthy_upstream.inc();
                record.failed("no_healthy_upstream");
                return synthetic(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "no healthy upstream",
                    record.request_id(),
                );
            }
        };
        let authority = selection.upstream.authority();
        let backend = UpstreamDurationLabels {
            pool: pool.id.to_string(),
            backend: authority.clone(),
        };
        let in_flight = shared
            .metrics
            .proxy
            .upstream_requests_in_flight
            .get_or_create(&backend)
            .clone();
        in_flight.inc();
        record.attempting(
            authority.clone(),
            BackendBusy {
                _least_request: selection.guard,
                in_flight,
            },
        );
        if attempt > 0 {
            let pool = PoolLabel {
                pool: pool.id.to_string(),
            };
            shared
                .metrics
                .proxy
                .upstream_retries
                .get_or_create(&pool)
                .inc();
        }

        // Build this attempt's upstream request.
        let upstream_req = if retryable {
            let mut b = Request::builder()
                .method(parts.method.clone())
                .version(version)
                .uri(&path_and_query);
            if let Some(h) = b.headers_mut() {
                *h = parts.headers.clone();
            }
            b.body(empty_body()).expect("build retryable request")
        } else {
            let body = streamed_body.take().expect("body consumed once");
            let mut b = Request::builder()
                .method(parts.method.clone())
                .version(version)
                .uri(&path_and_query);
            if let Some(h) = b.headers_mut() {
                *h = parts.headers.clone();
            }
            b.body(body).expect("build request")
        };

        let start = Instant::now();
        progress.attempt_started(start);
        let sending = shared.upstream.send(pool.scheme, &authority, upstream_req);
        let result = if record.is_grpc() {
            // A gRPC stream may have nothing to say, not even headers, for
            // as long as it likes: how long a call may take is the deadline
            // its client sets and enforces, not a proxy timeout. A backend
            // that died is noticed by the HTTP/2 keep-alive instead.
            Ok(sending.await)
        } else {
            tokio::select! {
                result = sending => Ok(result),
                _ = progress.overdue(&shared.timeouts) => Err(()),
            }
        };
        shared
            .metrics
            .proxy
            .upstream_request_duration_seconds
            .get_or_create(&backend)
            .observe(start.elapsed().as_secs_f64());

        match result {
            Ok(Ok(resp)) => {
                record.upstream_responded(forwarding_started.elapsed());
                record_upstream(shared, pool, &authority, resp.status().as_u16());
                return map_upstream_response(resp, ctx);
            }
            Ok(Err(e)) if e.kind == FailureKind::ConnectionLimit => {
                // The node is at `max_upstream_connections`. That is not the
                // backend's failure, and no other backend would fare better,
                // so neither count it against the backend nor retry.
                record_upstream_error(shared, pool, &authority, e.kind.as_str());
                tracing::debug!(error = %e, backend = %authority, "upstream connection refused");
                record.failed(failure_reason(e.kind));
                return synthetic(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "upstream connection limit",
                    record.request_id(),
                );
            }
            Ok(Err(e)) => {
                shared.metrics.proxy.upstream_connect_errors.inc();
                record_upstream_error(shared, pool, &authority, e.kind.as_str());
                record_upstream(shared, pool, &authority, 502);
                if attempt + 1 < max_attempts {
                    tracing::debug!(error = %e, backend = %authority, "upstream failed, retrying");
                    continue;
                }
                tracing::debug!(error = %e, backend = %authority, "upstream request failed");
                record.failed(failure_reason(e.kind));
                return synthetic(
                    StatusCode::BAD_GATEWAY,
                    "upstream error",
                    record.request_id(),
                );
            }
            Err(()) if progress.waiting_for_client() => {
                // Nothing has been sent to the backend for too long because
                // the client has not sent the rest of the body: the client
                // stalled, which is not the backend's failure. A backend
                // that stops taking the body is not: GFE does not ask the
                // client for more until the backend has taken what it has.
                tracing::debug!(backend = %authority, "request body stalled");
                record.failed("request_body_timeout");
                return synthetic(
                    StatusCode::REQUEST_TIMEOUT,
                    "request body timeout",
                    record.request_id(),
                );
            }
            Err(()) => {
                // Timeouts are not retried.
                record_upstream_error(shared, pool, &authority, "timeout");
                record_upstream(shared, pool, &authority, 504);
                tracing::debug!(backend = %authority, "upstream request timed out");
                record.failed("upstream_timeout");
                return synthetic(
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream timeout",
                    record.request_id(),
                );
            }
        }
    }

    // Unreachable in practice (the loop always returns), but keep the type
    // checker happy and fail safe.
    record.failed("upstream_error");
    synthetic(
        StatusCode::BAD_GATEWAY,
        "upstream error",
        record.request_id(),
    )
}

/// Marks a backend as busy with one request, for least-request selection and
/// for the in-flight gauge, until dropped.
struct BackendBusy {
    _least_request: InflightGuard,
    in_flight: Gauge,
}

impl Drop for BackendBusy {
    fn drop(&mut self) {
        self.in_flight.dec();
    }
}

/// The access-log `error` for a request that failed with `kind`.
fn failure_reason(kind: FailureKind) -> &'static str {
    match kind {
        FailureKind::ConnectTimeout => "upstream_connect_timeout",
        FailureKind::ConnectRefused => "upstream_connect_refused",
        FailureKind::ConnectError => "upstream_connect_error",
        FailureKind::Tls => "upstream_tls",
        FailureKind::Reset => "upstream_reset",
        FailureKind::ConnectionLimit => "upstream_connection_limit",
        FailureKind::Other => "upstream_error",
    }
}

fn record_upstream_error(shared: &crate::ProxyShared, pool: &Pool, backend: &str, kind: &str) {
    shared
        .metrics
        .proxy
        .upstream_errors
        .get_or_create(&UpstreamErrorLabels {
            pool: pool.id.to_string(),
            backend: backend.to_string(),
            kind: kind.to_string(),
        })
        .inc();
}

fn record_upstream(shared: &crate::ProxyShared, pool: &Pool, backend: &str, status: u16) {
    shared
        .metrics
        .proxy
        .upstream_requests
        .get_or_create(&UpstreamLabels {
            pool: pool.id.to_string(),
            backend: backend.to_string(),
            status: status.to_string(),
        })
        .inc();
}

fn map_upstream_response(resp: Response<Incoming>, ctx: &ConnCtx) -> Response<RespBody> {
    let (mut parts, body) = resp.into_parts();
    strip_hop_by_hop(&mut parts.headers);

    // Inject HSTS on HTTPS responses if configured.
    if ctx.is_tls && !ctx.shared.tls.hsts.is_empty() {
        set_header(
            &mut parts.headers,
            "strict-transport-security",
            &ctx.shared.tls.hsts,
        );
    }

    Response::from_parts(parts, incoming_body(body))
}

/// Build a redirect response (e.g. HTTP→HTTPS).
pub fn redirect_response(
    scheme: &str,
    status: u16,
    host: &str,
    path_and_query: &str,
    request_id: &str,
) -> Response<RespBody> {
    let location = format!("{scheme}://{host}{path_and_query}");
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::PERMANENT_REDIRECT);
    let mut resp = Response::new(full_body(Bytes::new()));
    *resp.status_mut() = code;
    if let Ok(v) = HeaderValue::from_str(&location) {
        resp.headers_mut().insert(http::header::LOCATION, v);
    }
    if let Ok(v) = HeaderValue::from_str(request_id) {
        resp.headers_mut().insert("x-request-id", v);
    }
    resp
}

/// Build a fixed-status response with an optional body.
pub fn fixed_response(status: u16, body: &str, request_id: &str) -> Response<RespBody> {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    let mut resp = Response::new(full_body(Bytes::from(body.to_string())));
    *resp.status_mut() = code;
    if let Ok(v) = HeaderValue::from_str(request_id) {
        resp.headers_mut().insert("x-request-id", v);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn te_trailers_asks_for_trailers() {
        assert!(asks_for_trailers(&headers(&[("te", "trailers")])));
        assert!(asks_for_trailers(&headers(&[("te", "Trailers")])));
    }

    #[test]
    fn other_te_values_do_not_ask_for_trailers() {
        assert!(!asks_for_trailers(&headers(&[])));
        assert!(!asks_for_trailers(&headers(&[("te", "gzip")])));
        assert!(!asks_for_trailers(&headers(&[("te", "trailers, gzip")])));
    }

    #[test]
    fn strips_hop_by_hop_and_connection_named_headers() {
        let mut map = headers(&[
            ("connection", "x-internal"),
            ("x-internal", "1"),
            ("te", "trailers"),
            ("accept", "*/*"),
        ]);

        strip_hop_by_hop(&mut map);

        assert_eq!(map.len(), 1);
        assert!(map.contains_key("accept"));
    }
}
