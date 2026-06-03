//! Request/response forwarding: hop-by-hop header hygiene, forwarding
//! headers, the upstream call, and mapping the upstream response back.

use crate::errors::{full_body, incoming_body, synthetic, RespBody};
use crate::ConnCtx;
use bytes::Bytes;
use gfe_metrics::{UpstreamDurationLabels, UpstreamLabels};
use gfe_upstream::{BoxError, Pool};
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
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

/// Whether the request carries no body (so it is trivially safe to retry).
fn body_is_empty(headers: &HeaderMap) -> bool {
    let cl_zero = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        == Some(0);
    let no_cl = !headers.contains_key(http::header::CONTENT_LENGTH);
    let no_te = !headers.contains_key(http::header::TRANSFER_ENCODING);
    cl_zero || (no_cl && no_te)
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
pub async fn forward(
    ctx: &ConnCtx,
    pool: &Arc<Pool>,
    route_id: &str,
    req: Request<Incoming>,
    host: &str,
    request_id: &str,
) -> Response<RespBody> {
    let shared = &ctx.shared;
    let hash_key = Some(gfe_upstream::policy::hash64(ctx.client_ip));
    let proto = if ctx.is_tls { "https" } else { "http" };

    let (mut parts, body) = req.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    append_forwarded_for(&mut parts.headers, &ctx.client_ip.to_string());
    set_header(&mut parts.headers, "x-forwarded-proto", proto);
    set_header(&mut parts.headers, "x-forwarded-host", host);
    set_header(
        &mut parts.headers,
        "forwarded",
        &format!("for={};host={};proto={}", ctx.client_ip, host, proto),
    );
    if !parts.headers.contains_key("x-request-id") {
        set_header(&mut parts.headers, "x-request-id", request_id);
    }

    let retryable = is_idempotent(&parts.method) && body_is_empty(&parts.headers);
    let max_attempts = if retryable { 2 } else { 1 };
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    // For the non-retryable path we forward the real (streamed) body exactly
    // once, so move it into an Option consumed on the single attempt.
    let mut streamed_body = if retryable {
        None
    } else {
        Some(body.map_err(|e| Box::new(e) as BoxError).boxed())
    };

    for attempt in 0..max_attempts {
        let selection = match pool.select(&shared.health, hash_key) {
            Some(s) => s,
            None => {
                shared.metrics.proxy.no_healthy_upstream.inc();
                return synthetic(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "no healthy upstream",
                    request_id,
                );
            }
        };
        let _inflight = selection.guard;
        let authority = selection.upstream.authority();

        // Build this attempt's upstream request.
        let upstream_req = if retryable {
            let mut b = Request::builder()
                .method(parts.method.clone())
                .uri(&path_and_query);
            if let Some(h) = b.headers_mut() {
                *h = parts.headers.clone();
            }
            b.body(empty_body()).expect("build retryable request")
        } else {
            let body = streamed_body.take().expect("body consumed once");
            let mut b = Request::builder()
                .method(parts.method.clone())
                .uri(&path_and_query);
            if let Some(h) = b.headers_mut() {
                *h = parts.headers.clone();
            }
            b.body(body).expect("build request")
        };

        let start = Instant::now();
        let result = tokio::time::timeout(
            shared.timeouts.request_total,
            shared.upstream.send(pool.scheme, &authority, upstream_req),
        )
        .await;
        shared
            .metrics
            .proxy
            .upstream_request_duration_seconds
            .get_or_create(&UpstreamDurationLabels {
                pool: pool.id.to_string(),
                backend: authority.clone(),
            })
            .observe(start.elapsed().as_secs_f64());

        match result {
            Ok(Ok(resp)) => {
                record_upstream(shared, route_id, pool, &authority, resp.status().as_u16());
                return map_upstream_response(resp, ctx, request_id);
            }
            Ok(Err(e)) => {
                shared.metrics.proxy.upstream_connect_errors.inc();
                record_upstream(shared, route_id, pool, &authority, 502);
                if attempt + 1 < max_attempts {
                    tracing::debug!(error = %e, backend = %authority, "upstream failed, retrying");
                    continue;
                }
                tracing::debug!(error = %e, backend = %authority, "upstream request failed");
                return synthetic(StatusCode::BAD_GATEWAY, "upstream error", request_id);
            }
            Err(_) => {
                // Timeouts are not retried.
                record_upstream(shared, route_id, pool, &authority, 504);
                tracing::debug!(backend = %authority, "upstream request timed out");
                return synthetic(StatusCode::GATEWAY_TIMEOUT, "upstream timeout", request_id);
            }
        }
    }

    // Unreachable in practice (the loop always returns), but keep the type
    // checker happy and fail safe.
    synthetic(StatusCode::BAD_GATEWAY, "upstream error", request_id)
}

fn record_upstream(
    shared: &crate::ProxyShared,
    _route_id: &str,
    pool: &Pool,
    backend: &str,
    status: u16,
) {
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

fn map_upstream_response(
    resp: Response<Incoming>,
    ctx: &ConnCtx,
    _request_id: &str,
) -> Response<RespBody> {
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
