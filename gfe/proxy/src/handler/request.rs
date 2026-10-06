//! The request as GFE reads it and as the backend gets it: its id, whether
//! it is a gRPC call, what makes it one GFE refuses to forward (a target
//! that is not a path, a protocol upgrade), and the head sent on, without
//! the client's hop-by-hop headers and with GFE's forwarding headers.
//!
//! Which backend the request goes to, and over which protocol, is decided
//! in `forward`; the client then names the backend (`:authority` over
//! HTTP/2) and drops `Host` where it would contradict it.

use netkit_http::header::{CONNECTION, CONTENT_TYPE, HOST, TE, UPGRADE};
use netkit_http::request::Parts;
use netkit_http::{HeaderMap, HeaderName, HeaderValue, Uri};
use std::net::IpAddr;

/// The longest client-supplied `X-Request-Id` GFE adopts.
const MAX_REQUEST_ID_LEN: usize = 128;

/// Headers that must not be forwarded across a proxy hop (RFC 9110 §7.6.1).
const HOP_BY_HOP: [&str; 9] = [
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

/// The client's `X-Request-Id` if it is a usable one (non-empty, printable
/// ASCII, at most 128 bytes), else a new random 128-bit id in hex.
pub fn request_id(headers: &HeaderMap) -> String {
    let supplied = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|id| !id.is_empty() && id.len() <= MAX_REQUEST_ID_LEN && id.is_ascii());
    match supplied {
        Some(id) => id.to_string(),
        None => {
            let a: u64 = rand::random();
            let b: u64 = rand::random();
            format!("{a:016x}{b:016x}")
        }
    }
}

/// Whether the request is a gRPC call, going by its content type.
pub fn is_grpc(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .is_some_and(|value| value.as_bytes().starts_with(b"application/grpc"))
}

/// Whether a request target names a path on the origin server: origin form
/// (`/path`) or absolute form (`http://host/path`). The asterisk form of
/// `OPTIONS *` and the authority form of `CONNECT` do not, and GFE forwards
/// neither.
pub fn names_a_path(target: &Uri) -> bool {
    target.path().starts_with('/')
}

/// Whether the request asks to switch to a protocol it cannot do without
/// (RFC 9110 §7.8), as a WebSocket handshake does: it names `upgrade` among
/// its `Connection` options and says to what in an `Upgrade` header.
///
/// An offer to switch to HTTP/2 (`Upgrade: h2c`, which `curl --http2` sends
/// to a cleartext URL) is not one: the client expects a server that does not
/// take it up to answer over HTTP/1.1, which is what happens once the
/// hop-by-hop headers are stripped.
pub fn asks_for_upgrade(headers: &HeaderMap) -> bool {
    let names_upgrade = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|option| option.trim().eq_ignore_ascii_case("upgrade"));
    let to_another_protocol = headers
        .get_all(UPGRADE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|protocol| !protocol.trim().eq_ignore_ascii_case("h2c"));
    names_upgrade && to_another_protocol
}

/// Whether the request carries `te: trailers`, and nothing else in `te`.
///
/// `TE` is a hop-by-hop header, but `trailers` is the one value HTTP/2
/// permits (RFC 9113 §8.2.2), and it is not optional for gRPC: clients must
/// send it and servers use it to detect proxies that cannot relay trailers.
pub fn asks_for_trailers(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(TE).iter();
    match (values.next(), values.next()) {
        (Some(only), None) => only.as_bytes().eq_ignore_ascii_case(b"trailers"),
        _ => false,
    }
}

/// Remove the hop-by-hop headers of a request or response head, and those
/// its `Connection` header names, whatever they are: a header the sender
/// says is for this hop only does not cross it.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
    for name in named {
        headers.remove(name);
    }
}

/// What the forwarding headers say about a request.
#[derive(Debug)]
pub struct Forwarding<'a> {
    /// The client's address.
    pub client: IpAddr,
    /// `https` when the request arrived over TLS, else `http`.
    pub proto: &'static str,
    /// The host the request is for, as routed.
    pub host: &'a str,
    /// The request's id, given to the backend when the client sent none.
    pub request_id: &'a str,
}

/// Turn the head of a client's request into the head the backend gets.
///
/// The client's hop-by-hop headers go, except `TE: trailers`, which GFE
/// may send on its own hop since it relays trailers. GFE adds
/// `X-Forwarded-For` (the client appended to what is there),
/// `X-Forwarded-Proto`, `X-Forwarded-Host`, `Forwarded`, and an
/// `X-Request-Id` when the client sent none. GFE adds no `Via`, as `v1.1.0`
/// added none.
///
/// `Host` is the host the client asked for, as HAProxy hands it to backends,
/// whatever protocol the client spoke: the authority of the request target
/// when there is one (always over HTTP/2, where it is `:authority`; an
/// HTTP/1.1 request in absolute form), else the `Host` header as the client
/// sent it, port included.
pub fn to_backend(head: &mut Parts, forwarding: &Forwarding<'_>) {
    let asks_for_trailers = asks_for_trailers(&head.headers);
    let headers = &mut head.headers;
    strip_hop_by_hop(headers);
    if asks_for_trailers {
        headers.insert(TE, HeaderValue::from_static("trailers"));
    }
    let client = forwarding.client.to_string();
    let forwarded_for = match headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
    {
        Some(existing) => format!("{existing}, {client}"),
        None => client.clone(),
    };
    set(headers, "x-forwarded-for", &forwarded_for);
    set(headers, "x-forwarded-proto", forwarding.proto);
    set(headers, "x-forwarded-host", forwarding.host);
    let forwarded = format!(
        "for={client};host={};proto={}",
        forwarding.host, forwarding.proto
    );
    set(headers, "forwarded", &forwarded);
    if !headers.contains_key("x-request-id") {
        set(headers, "x-request-id", forwarding.request_id);
    }
    // Any userinfo (`user@`) is not part of the host.
    let target_host = head.uri.authority().and_then(|authority| {
        let host = authority.as_str().rsplit('@').next().unwrap_or_default();
        HeaderValue::from_str(host).ok()
    });
    if let Some(host) = target_host {
        head.headers.insert(HOST, host);
    }
}

/// Set a header, leaving it out if `value` cannot be a header value (a host
/// or id that came from the client).
fn set(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(HeaderName::from_static(name), value);
    }
}

#[cfg(test)]
#[path = "request_test.rs"]
mod tests;
