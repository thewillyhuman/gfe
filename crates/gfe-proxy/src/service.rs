//! Per-request handling: route match → action (forward / redirect / fixed).

use crate::errors::{synthetic, RespBody};
use crate::forward::{fixed_response, forward, redirect_response};
use crate::record::RequestRecord;
use crate::ConnCtx;
use gfe_types::{PoolId, RouteAction};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use std::convert::Infallible;
use std::sync::Arc;

/// Handle one client request. Always returns `Ok`; failures become synthetic
/// responses so the hyper connection stays healthy.
///
/// The request is accounted for by a [`RequestRecord`], which reports it
/// (metrics and access log) once the response has been written out, or as
/// soon as this future is dropped because the client went away.
pub async fn handle_request(
    ctx: Arc<ConnCtx>,
    req: Request<Incoming>,
) -> Result<Response<RespBody>, Infallible> {
    let shared = ctx.shared.clone();
    let host = extract_host(&req, &ctx.sni);
    let mut record = RequestRecord::begin(ctx.clone(), &req, host, request_id(&req));
    let path = req.uri().path().to_string();

    // ACME http-01 challenge: served on the plaintext HTTP listener before
    // routing, so a cert can be issued for a host that has no cert yet.
    if !ctx.is_tls && path.starts_with(gfe_tls::ACME_CHALLENGE_PREFIX) {
        let resp = match ctx.shared.challenges.resolve_path(&path) {
            Some(key_auth) => fixed_response(200, &key_auth, record.request_id()),
            None => {
                record.failed("unknown_acme_challenge");
                synthetic(
                    StatusCode::NOT_FOUND,
                    "unknown acme challenge",
                    record.request_id(),
                )
            }
        };
        return Ok(record.respond(resp));
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
            .match_request(&ctx.listener_id, record.host(), &path)
            .map(|r| (r.id.to_string(), r.host.clone(), r.action.clone()))
    };

    let resp = match matched {
        None => {
            shared.metrics.proxy.no_route.inc();
            record.failed("no_route");
            synthetic(StatusCode::NOT_FOUND, "no route", record.request_id())
        }
        Some((route_id, host_pattern, action)) => {
            record.matched_route(route_id, host_pattern);
            match action {
                RouteAction::Forward(pool_id) => {
                    let pool = shared.pools.load().get(&PoolId(pool_id.clone())).cloned();
                    match pool {
                        Some(pool) => forward(&ctx, &pool, req, &mut record).await,
                        None => {
                            tracing::warn!(pool = %pool_id, "route references unknown pool");
                            record.failed("pool_not_found");
                            synthetic(
                                StatusCode::BAD_GATEWAY,
                                "pool not found",
                                record.request_id(),
                            )
                        }
                    }
                }
                RouteAction::Redirect(rd) => redirect_response(
                    &rd.scheme,
                    rd.status,
                    record.host(),
                    &path_and_query,
                    record.request_id(),
                ),
                RouteAction::Fixed(f) => fixed_response(f.status, &f.body, record.request_id()),
            }
        }
    };

    Ok(record.respond(resp))
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
