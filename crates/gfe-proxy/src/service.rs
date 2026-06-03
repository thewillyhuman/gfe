//! Per-request handling: route match → action (forward / redirect / fixed).

use crate::errors::{synthetic, RespBody};
use crate::forward::{fixed_response, forward, redirect_response};
use crate::ConnCtx;
use gfe_metrics::{RequestDurationLabels, RequestLabels};
use gfe_types::{PoolId, RouteAction};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;

/// Handle one client request. Always returns `Ok`; failures become synthetic
/// responses so the hyper connection stays healthy.
pub async fn handle_request(
    ctx: Arc<ConnCtx>,
    req: Request<Incoming>,
) -> Result<Response<RespBody>, Infallible> {
    let start = Instant::now();
    let shared = ctx.shared.clone();

    let request_id = request_id(&req);
    let host = extract_host(&req, &ctx.sni);
    let method = req.method().to_string();
    let path = req.uri().path().to_string();

    // ACME http-01 challenge: served on the plaintext HTTP listener before
    // routing, so a cert can be issued for a host that has no cert yet.
    if !ctx.is_tls && path.starts_with(gfe_tls::ACME_CHALLENGE_PREFIX) {
        if let Some(key_auth) = ctx.shared.challenges.resolve_path(&path) {
            return Ok(fixed_response(200, &key_auth, &request_id));
        }
        return Ok(synthetic(
            StatusCode::NOT_FOUND,
            "unknown acme challenge",
            &request_id,
        ));
    }
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    // Resolve the route without holding the ArcSwap guard across the await.
    let matched = {
        let routes = shared.routes.load();
        routes
            .match_request(&ctx.listener_id, &host, &path)
            .map(|r| (r.id.to_string(), r.host.clone(), r.action.clone()))
    };

    let (resp, route_label, host_label) = match matched {
        None => {
            shared.metrics.proxy.no_route.inc();
            (
                synthetic(StatusCode::NOT_FOUND, "no route", &request_id),
                "none".to_string(),
                "none".to_string(),
            )
        }
        Some((route_id, host_pattern, action)) => {
            let resp = match action {
                RouteAction::Forward(pool_id) => {
                    let pool = shared.pools.load().get(&PoolId(pool_id.clone())).cloned();
                    match pool {
                        Some(pool) => {
                            forward(&ctx, &pool, &route_id, req, &host, &request_id).await
                        }
                        None => {
                            tracing::warn!(pool = %pool_id, "route references unknown pool");
                            synthetic(StatusCode::BAD_GATEWAY, "pool not found", &request_id)
                        }
                    }
                }
                RouteAction::Redirect(rd) => {
                    redirect_response(&rd.scheme, rd.status, &host, &path_and_query, &request_id)
                }
                RouteAction::Fixed(f) => fixed_response(f.status, &f.body, &request_id),
            };
            (resp, route_id, host_pattern)
        }
    };

    // Record request metrics.
    let status = resp.status().as_u16();
    let elapsed = start.elapsed();
    shared
        .metrics
        .proxy
        .requests
        .get_or_create(&RequestLabels {
            listener: ctx.listener_id.to_string(),
            host: host_label.clone(),
            route: route_label.clone(),
            status: status.to_string(),
        })
        .inc();
    shared
        .metrics
        .proxy
        .request_duration_seconds
        .get_or_create(&RequestDurationLabels {
            listener: ctx.listener_id.to_string(),
            host: host_label,
            route: route_label.clone(),
        })
        .observe(elapsed.as_secs_f64());

    // Structured access log (one event per request) under a distinct target so
    // operators can route/sample it independently.
    tracing::info!(
        target: "gfe::access",
        client = %ctx.client_ip,
        proto = if ctx.is_tls { "https" } else { "http" },
        listener = %ctx.listener_id,
        host = %host,
        method = %method,
        path = %path,
        status = status,
        route = %route_label,
        request_id = %request_id,
        duration_ms = elapsed.as_millis() as u64,
        "request"
    );

    Ok(resp)
}

/// Extract the request host: prefer the URI authority (h2 / absolute-form),
/// then the `Host` header (h1), then the SNI.
fn extract_host<B>(req: &Request<B>, sni: &Option<String>) -> String {
    if let Some(h) = req.uri().host() {
        return h.to_ascii_lowercase();
    }
    if let Some(hv) = req.headers().get(hyper::header::HOST) {
        if let Ok(s) = hv.to_str() {
            return s.split(':').next().unwrap_or("").to_ascii_lowercase();
        }
    }
    sni.clone().unwrap_or_default()
}

/// Take a client-supplied `X-Request-Id` if valid, else generate one.
fn request_id<B>(req: &Request<B>) -> String {
    if let Some(v) = req.headers().get("x-request-id") {
        if let Ok(s) = v.to_str() {
            if !s.is_empty() && s.len() <= 128 && s.is_ascii() {
                return s.to_string();
            }
        }
    }
    let a: u64 = rand::random();
    let b: u64 = rand::random();
    format!("{a:016x}{b:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(host_header: Option<&str>, uri: &str) -> Request<()> {
        let mut b = Request::builder().uri(uri);
        if let Some(h) = host_header {
            b = b.header(hyper::header::HOST, h);
        }
        b.body(()).unwrap()
    }

    #[test]
    fn host_from_authority() {
        let r = req(None, "http://API.example.org/x");
        assert_eq!(extract_host(&r, &None), "api.example.org");
    }

    #[test]
    fn host_from_header_then_sni() {
        let r = req(Some("Host.Example.org:443"), "/path");
        assert_eq!(extract_host(&r, &None), "host.example.org");
        let r2 = req(None, "/path");
        assert_eq!(
            extract_host(&r2, &Some("sni.example.org".into())),
            "sni.example.org"
        );
    }

    #[test]
    fn request_id_kept_or_generated() {
        let r = req(None, "/");
        let gen = request_id(&r);
        assert_eq!(gen.len(), 32);

        let mut b = Request::builder().uri("/");
        b = b.header("x-request-id", "client-123");
        let r2 = b.body(()).unwrap();
        assert_eq!(request_id(&r2), "client-123");
    }
}
