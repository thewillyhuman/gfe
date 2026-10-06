use super::*;
use http::HeaderValue;

fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.append(*name, HeaderValue::from_static(value));
    }
    map
}

#[test]
fn keeps_a_usable_client_request_id() {
    assert_eq!(
        request_id(&headers(&[("x-request-id", "client-123")])),
        "client-123"
    );
}

#[test]
fn generates_a_request_id_when_the_client_has_none() {
    let id = request_id(&headers(&[]));

    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|b| b.is_ascii_hexdigit()), "{id}");
}

#[test]
fn replaces_an_unusable_client_request_id() {
    let long = "x".repeat(129);
    let mut map = HeaderMap::new();
    map.insert("x-request-id", HeaderValue::from_str(&long).unwrap());

    assert_ne!(request_id(&map), long);
    assert_ne!(request_id(&headers(&[("x-request-id", "")])), "");
}

#[test]
fn recognises_grpc_by_content_type() {
    assert!(is_grpc(&headers(&[("content-type", "application/grpc")])));
    assert!(is_grpc(&headers(&[(
        "content-type",
        "application/grpc+proto"
    )])));
    assert!(!is_grpc(&headers(&[("content-type", "application/json")])));
    assert!(!is_grpc(&headers(&[])));
}

#[test]
fn origin_and_absolute_form_name_a_path() {
    assert!(names_a_path("/x".as_bytes()));
    assert!(names_a_path("http://a.example.org/x".as_bytes()));
}

#[test]
fn asterisk_and_authority_form_name_no_path() {
    assert!(!names_a_path("*".as_bytes()));
    assert!(!names_a_path("a.example.org:443".as_bytes()));
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
fn websocket_handshake_asks_for_upgrade() {
    assert!(asks_for_upgrade(&headers(&[
        ("connection", "Upgrade"),
        ("upgrade", "websocket"),
    ])));
    assert!(asks_for_upgrade(&headers(&[
        ("connection", "keep-alive, UPGRADE"),
        ("upgrade", "websocket"),
    ])));
}

#[test]
fn upgrade_needs_both_connection_option_and_upgrade_header() {
    assert!(!asks_for_upgrade(&headers(&[("connection", "keep-alive")])));
    assert!(!asks_for_upgrade(&headers(&[("connection", "upgrade")])));
    assert!(!asks_for_upgrade(&headers(&[("upgrade", "websocket")])));
    assert!(!asks_for_upgrade(&headers(&[
        ("connection", "upgrades"),
        ("upgrade", "websocket"),
    ])));
}

#[test]
fn offer_to_switch_to_http2_does_not_ask_for_upgrade() {
    assert!(!asks_for_upgrade(&headers(&[
        ("connection", "Upgrade, HTTP2-Settings"),
        ("upgrade", "h2c"),
    ])));
    assert!(asks_for_upgrade(&headers(&[
        ("connection", "Upgrade"),
        ("upgrade", "h2c, websocket"),
    ])));
}

#[test]
fn head_size_counts_the_request_line_and_header_lines() {
    let mut req = RequestHeader::build("GET", b"/", None).unwrap();
    req.insert_header("host", "a.example.org").unwrap();

    // "GET / HTTP/1.1\r\n" + "host: a.example.org\r\n" + "\r\n"
    assert_eq!(head_size(&req), 16 + 21 + 2);
}
