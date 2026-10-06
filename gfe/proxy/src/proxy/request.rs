//! What GFE reads off a request head before routing it: its id, whether it
//! is a gRPC call, and what makes it one GFE refuses to forward (a target
//! that is not a path, a protocol upgrade, a head that is too large).

use http::HeaderMap;
use http::header::{CONNECTION, CONTENT_TYPE, TE, UPGRADE};
use pingora_http::RequestHeader;

/// The longest client-supplied `X-Request-Id` GFE adopts.
const MAX_REQUEST_ID_LEN: usize = 128;

/// The client's `X-Request-Id` if it is a usable one (non-empty, printable
/// ASCII, at most 128 bytes), else a new random 128-bit id in hex.
pub(crate) fn request_id(headers: &HeaderMap) -> String {
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
pub(crate) fn is_grpc(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .is_some_and(|value| value.as_bytes().starts_with(b"application/grpc"))
}

/// Whether a request target names a path on the origin server: origin form
/// (`/path`) or absolute form (`http://host/path`). The asterisk form of
/// `OPTIONS *` and the authority form of `CONNECT` do not, and GFE forwards
/// neither.
///
/// It reads the target as the client sent it (`raw_target`): Pingora keeps
/// an absolute-form authority out of the parsed URI, and gives `*` a path.
pub(crate) fn names_a_path(raw_target: &[u8]) -> bool {
    raw_target.starts_with(b"/") || raw_target.windows(3).any(|w| w == b"://")
}

/// Whether the request asks to switch to a protocol it cannot do without
/// (RFC 9110 §7.8), as a WebSocket handshake does: it names `upgrade` among
/// its `Connection` options and says to what in an `Upgrade` header.
///
/// An offer to switch to HTTP/2 (`Upgrade: h2c`, which `curl --http2` sends
/// to a cleartext URL) is not one: the client expects a server that does not
/// take it up to answer over HTTP/1.1, which is what happens once the
/// hop-by-hop headers are stripped.
pub(crate) fn asks_for_upgrade(headers: &HeaderMap) -> bool {
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
pub(crate) fn asks_for_trailers(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(TE).iter();
    match (values.next(), values.next()) {
        (Some(only), None) => only.as_bytes().eq_ignore_ascii_case(b"trailers"),
        _ => false,
    }
}

/// The size of a request head as HTTP/1.1 spells it: the request line and
/// every header line with their separators. What `max_header_bytes` bounds.
///
/// Pingora has parsed the head by the time GFE sees it, so this is computed
/// from the parsed head rather than counted on the wire; for an HTTP/2
/// request it is the size the same head would have over HTTP/1.1.
pub(crate) fn head_size(req: &RequestHeader) -> usize {
    // "METHOD SP target SP HTTP/1.1 CRLF", then "name: value CRLF" per
    // header, then the empty line.
    let request_line = req.method.as_str().len() + 1 + req.raw_path().len() + 1 + 8 + 2;
    let headers: usize = req
        .headers
        .iter()
        .map(|(name, value)| name.as_str().len() + 2 + value.len() + 2)
        .sum();
    request_line + headers + 2
}

#[cfg(test)]
#[path = "request_test.rs"]
mod tests;
