//! Per-request handling: route match → action (forward / redirect / fixed).

use crate::errors::{grpc_failure, synthetic, GrpcCode, RespBody};
use crate::forward::{fixed_response, forward, redirect_response};
use crate::record::RequestRecord;
use crate::ConnCtx;
use gfe_types::{PoolId, RouteAction};
use hyper::body::Incoming;
use hyper::header::HOST;
use hyper::http::uri::Authority;
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
    let host = request_host(&req, ctx.sni.as_deref()).and_then(|host| covered_by_sni(&ctx, host));
    let logged_host = match &host {
        Ok(host) => host.clone(),
        Err(e) => e.host().to_string(),
    };
    let mut record = RequestRecord::begin(ctx.clone(), &req, logged_host, request_id(&req));
    if let Err(e) = host {
        record.failed(e.reason());
        let resp = synthetic(e.status(), e.message(), record.request_id());
        let resp = in_callers_protocol(resp, &record);
        return Ok(record.respond(resp));
    }
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

    let resp = in_callers_protocol(resp, &record);
    Ok(record.respond(resp))
}

/// A gRPC client reads a call's outcome from `grpc-status`, not from the HTTP
/// status. A response GFE generated for a gRPC call because it could not
/// serve it is therefore turned into a gRPC failure carrying the same reason.
fn in_callers_protocol(resp: Response<RespBody>, record: &RequestRecord) -> Response<RespBody> {
    match record.failure() {
        Some(reason) if record.is_grpc() => grpc_failure(
            GrpcCode::for_http_status(resp.status()),
            &format!("gfe: {reason}"),
            record.request_id(),
        ),
        _ => resp,
    }
}

/// Why a request's host cannot be used to route it. GFE answers such a
/// request itself.
#[derive(Debug, PartialEq, Eq)]
enum HostError {
    /// The request target's authority and the `Host` header name different
    /// hosts; `target` is the former.
    Conflict { target: String },
    /// Nothing names the host: no authority in the target, no valid `Host`
    /// header and no SNI.
    Missing,
    /// `host` is not served by the certificate the client accepted for the
    /// connection's SNI.
    Misdirected { host: String },
}

impl HostError {
    fn status(&self) -> StatusCode {
        match self {
            HostError::Conflict { .. } | HostError::Missing => StatusCode::BAD_REQUEST,
            // Tells a client that reused a connection to retry on a new one.
            HostError::Misdirected { .. } => StatusCode::MISDIRECTED_REQUEST,
        }
    }

    /// The access-log `error`.
    fn reason(&self) -> &'static str {
        match self {
            HostError::Conflict { .. } => "host_conflict",
            HostError::Missing => "host_missing",
            HostError::Misdirected { .. } => "misdirected_request",
        }
    }

    fn message(&self) -> &'static str {
        match self {
            HostError::Conflict { .. } => "conflicting host",
            HostError::Missing => "missing host",
            HostError::Misdirected { .. } => "misdirected request",
        }
    }

    /// The host the request is logged under.
    fn host(&self) -> &str {
        match self {
            HostError::Conflict { target } => target,
            HostError::Missing => "",
            HostError::Misdirected { host } => host,
        }
    }
}

/// The host a request is for, lowercased and without its port: the request
/// target's authority (HTTP/2 `:authority`, HTTP/1 absolute form), else the
/// `Host` header, else the SNI.
///
/// A request carrying both an authority and a `Host` header is refused
/// unless they name the same host, and the same port when both carry one:
/// otherwise it would be routed by one and forwarded with the other.
fn request_host<B>(req: &Request<B>, sni: Option<&str>) -> Result<String, HostError> {
    let header = req.headers().get(HOST).map(|value| {
        value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<Authority>().ok())
    });
    match (req.uri().authority(), header) {
        (Some(target), Some(header)) => {
            let agree = header.is_some_and(|header| {
                header.host().eq_ignore_ascii_case(target.host())
                    && match (header.port_u16(), target.port_u16()) {
                        (Some(a), Some(b)) => a == b,
                        _ => true,
                    }
            });
            let target = target.host().to_ascii_lowercase();
            if agree {
                Ok(target)
            } else {
                Err(HostError::Conflict { target })
            }
        }
        (Some(target), None) => Ok(target.host().to_ascii_lowercase()),
        (None, Some(Some(header))) => Ok(header.host().to_ascii_lowercase()),
        (None, Some(None)) => Err(HostError::Missing),
        (None, None) => sni.map(str::to_ascii_lowercase).ok_or(HostError::Missing),
    }
}

/// On a TLS connection, a request for another host than the SNI is served
/// only if the certificate the client accepted for the SNI is also the one
/// for `host`: that client is reusing the connection for a name it trusts
/// the connection for (HTTP/2 connection coalescing). Anything else could
/// reach a tenant over another tenant's certificate.
fn covered_by_sni(ctx: &ConnCtx, host: String) -> Result<String, HostError> {
    match &ctx.sni {
        Some(sni)
            if !sni.eq_ignore_ascii_case(&host)
                && !ctx.shared.resolver.current().same_certificate(sni, &host) =>
        {
            Err(HostError::Misdirected { host })
        }
        _ => Ok(host),
    }
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
        assert_eq!(request_host(&r, None), Ok("api.example.org".into()));
    }

    #[test]
    fn host_from_header_then_sni() {
        let r = req(Some("Host.Example.org:443"), "/path");
        assert_eq!(request_host(&r, None), Ok("host.example.org".into()));
        let r2 = req(None, "/path");
        assert_eq!(
            request_host(&r2, Some("sni.example.org")),
            Ok("sni.example.org".into())
        );
    }

    #[test]
    fn authority_and_host_header_naming_the_same_host_agree() {
        let r = req(Some("API.example.org"), "http://api.example.org:8080/x");
        assert_eq!(request_host(&r, None), Ok("api.example.org".into()));
    }

    #[test]
    fn authority_and_host_header_naming_different_hosts_conflict() {
        let r = req(Some("internal.example.org"), "http://public.example.org/");
        assert_eq!(
            request_host(&r, None),
            Err(HostError::Conflict {
                target: "public.example.org".into()
            })
        );
    }

    #[test]
    fn authority_and_host_header_naming_different_ports_conflict() {
        let r = req(Some("a.example.org:8443"), "http://a.example.org:443/");
        assert!(matches!(
            request_host(&r, None),
            Err(HostError::Conflict { .. })
        ));
    }

    #[test]
    fn no_authority_no_host_header_and_no_sni_is_missing() {
        let r = req(None, "/path");
        assert_eq!(request_host(&r, None), Err(HostError::Missing));
    }

    #[test]
    fn unparseable_host_header_is_missing() {
        let r = req(Some("a b"), "/path");
        assert_eq!(
            request_host(&r, Some("sni.example.org")),
            Err(HostError::Missing)
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
