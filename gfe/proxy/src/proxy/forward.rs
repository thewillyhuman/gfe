//! What a forwarded request and its response look like on the other side
//! of GFE: the forwarding headers, the host the backend is told, and the
//! headers that do not cross a proxy hop.
//!
//! Pingora has already removed the standard hop-by-hop fields, and those
//! the client's `Connection` header names, from the request it hands
//! `upstream_request_filter` (`HttpUpstreamRequestPolicy`, the default
//! policy). What is left to GFE is what that policy does not do the way
//! GFE always has: keep `TE: trailers`, and choose the host.

use http::header::{CONNECTION, HOST, TE};
use http::{HeaderName, HeaderValue, Uri, Version};
use pingora_error::Result;
use pingora_http::{RequestHeader, ResponseHeader};
use std::net::IpAddr;

/// What the forwarding headers say about a request.
#[derive(Debug)]
pub(crate) struct Forwarding<'a> {
    /// The client's address.
    pub(crate) client: IpAddr,
    /// `https` when the request arrived over TLS, else `http`.
    pub(crate) proto: &'static str,
    /// The host the request is for, as routed.
    pub(crate) host: &'a str,
    /// The request's id, given to the backend when the client sent none.
    pub(crate) request_id: &'a str,
    /// Whether the client sent `TE: trailers`, which is kept.
    pub(crate) asks_for_trailers: bool,
}

/// Add the forwarding headers to the request sent to the backend:
/// `X-Forwarded-For` (the client appended), `X-Forwarded-Proto`,
/// `X-Forwarded-Host`, `Forwarded`, an `X-Request-Id` when the client sent
/// none, and `TE: trailers` when the client asked for trailers.
pub(crate) fn add_forwarding_headers(req: &mut RequestHeader, f: &Forwarding<'_>) -> Result<()> {
    if f.asks_for_trailers {
        // GFE relays trailers, so it may make this request on its own hop.
        req.insert_header(TE, "trailers")?;
    }
    let forwarded_for = match req
        .headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
    {
        Some(existing) => format!("{existing}, {}", f.client),
        None => f.client.to_string(),
    };
    set(req, "x-forwarded-for", &forwarded_for)?;
    set(req, "x-forwarded-proto", f.proto)?;
    set(req, "x-forwarded-host", f.host)?;
    let forwarded = format!("for={};host={};proto={}", f.client, f.host, f.proto);
    set(req, "forwarded", &forwarded)?;
    if !req.headers.contains_key("x-request-id") {
        set(req, "x-request-id", f.request_id)?;
    }
    Ok(())
}

/// Make the request's target its origin form, and its `Host` the host the
/// backend is told.
///
/// Over HTTP/1.1 that is the host the client asked for, as HAProxy hands it
/// to backends, whatever protocol the client spoke: the authority of the
/// request target when there is one (always over HTTP/2, where it is
/// `:authority`; an HTTP/1.1 request in absolute form), else the `Host`
/// header as the client sent it, port included.
///
/// Over HTTP/2 the backend is named by `:authority`, which is its own
/// address `backend` (`host:port`); Pingora builds `:authority` from `Host`
/// and sends no `Host`, which would contradict it.
pub(crate) fn set_target_and_host(req: &mut RequestHeader, backend: &str) -> Result<()> {
    // Any userinfo (`user@`) is not part of the host.
    let requested = req
        .uri
        .authority()
        .map(|authority| authority.as_str().rsplit('@').next().unwrap_or_default())
        .and_then(|host| HeaderValue::from_str(host).ok());
    let origin_form = req
        .uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/"));
    req.set_uri(Uri::from(origin_form));
    if req.version == Version::HTTP_2 {
        req.insert_header(HOST, backend)?;
    } else if let Some(host) = requested {
        req.insert_header(HOST, host)?;
    }
    Ok(())
}

/// Response headers that do not cross a proxy hop and that the engine does
/// not already deal with (it writes `Connection` and the framing headers of
/// its own response).
const RESPONSE_HOP_BY_HOP: [&str; 6] = [
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "te",
    "trailer",
    "upgrade",
];

/// Remove from a backend's response the hop-by-hop headers (RFC 9110
/// §7.6.1) and those its `Connection` header names. `Connection` itself and
/// the framing headers are left to Pingora, which rewrites them for the
/// client's connection.
pub(crate) fn strip_response_hop_by_hop(resp: &mut ResponseHeader) {
    let named: Vec<HeaderName> = resp
        .headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .filter(|name| !is_framing(name))
        .collect();
    for name in RESPONSE_HOP_BY_HOP {
        resp.remove_header(name);
    }
    for name in &named {
        resp.remove_header(name);
    }
}

/// Whether removing `name` would change how the response is delimited.
fn is_framing(name: &HeaderName) -> bool {
    name == http::header::CONTENT_LENGTH
        || name == http::header::TRANSFER_ENCODING
        || name == CONNECTION
}

/// Add `Strict-Transport-Security: hsts` to a response, unless `hsts` is
/// empty (HSTS disabled).
pub(crate) fn add_hsts(resp: &mut ResponseHeader, hsts: &str) -> Result<()> {
    if hsts.is_empty() {
        return Ok(());
    }
    match HeaderValue::from_str(hsts) {
        Ok(value) => resp.insert_header("strict-transport-security", value),
        Err(_) => Ok(()),
    }
}

/// Set a header, leaving it out if `value` cannot be a header value (a host
/// or id that came from the client).
fn set(req: &mut RequestHeader, name: &'static str, value: &str) -> Result<()> {
    match HeaderValue::from_str(value) {
        Ok(value) => req.insert_header(name, value),
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
#[path = "forward_test.rs"]
mod tests;
