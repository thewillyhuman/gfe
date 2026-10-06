use super::*;
use netkit_http::Request;

fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.append(*name, HeaderValue::from_static(value));
    }
    map
}

/// The head of a request for `target` with `pairs` as its headers.
fn head(target: &str, pairs: &[(&'static str, &'static str)]) -> Parts {
    let (mut parts, ()) = Request::builder()
        .uri(target)
        .body(())
        .unwrap()
        .into_parts();
    parts.headers = headers(pairs);
    parts
}

fn forwarding() -> Forwarding<'static> {
    Forwarding {
        client: "192.0.2.7".parse().unwrap(),
        proto: "https",
        host: "a.example.org",
        request_id: "abc123",
    }
}

fn header<'a>(parts: &'a Parts, name: &str) -> &'a str {
    parts.headers[name].to_str().unwrap()
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
    assert!(names_a_path(&Uri::from_static("/x")));
    assert!(names_a_path(&Uri::from_static("http://a.example.org/x")));
}

#[test]
fn asterisk_and_authority_form_name_no_path() {
    assert!(!names_a_path(&Uri::from_static("*")));
    assert!(!names_a_path(&Uri::from_static("a.example.org:443")));
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
fn strips_hop_by_hop_and_connection_named_headers() {
    let mut map = headers(&[
        ("connection", "x-internal"),
        ("x-internal", "1"),
        ("te", "trailers"),
        ("keep-alive", "timeout=5"),
        ("transfer-encoding", "chunked"),
        ("accept", "*/*"),
    ]);

    strip_hop_by_hop(&mut map);

    assert_eq!(map.len(), 1);
    assert!(map.contains_key("accept"));
}

#[test]
fn adds_the_forwarding_headers() {
    let mut parts = head("/", &[("host", "a.example.org")]);

    to_backend(&mut parts, &forwarding());

    assert_eq!(header(&parts, "x-forwarded-for"), "192.0.2.7");
    assert_eq!(header(&parts, "x-forwarded-proto"), "https");
    assert_eq!(header(&parts, "x-forwarded-host"), "a.example.org");
    assert_eq!(
        header(&parts, "forwarded"),
        "for=192.0.2.7;host=a.example.org;proto=https"
    );
    assert_eq!(header(&parts, "x-request-id"), "abc123");
    assert!(!parts.headers.contains_key("te"));
    assert!(!parts.headers.contains_key("via"));
}

#[test]
fn appends_the_client_to_an_existing_x_forwarded_for() {
    let mut parts = head("/", &[("x-forwarded-for", "198.51.100.1")]);

    to_backend(&mut parts, &forwarding());

    assert_eq!(header(&parts, "x-forwarded-for"), "198.51.100.1, 192.0.2.7");
}

#[test]
fn keeps_the_clients_request_id() {
    let mut parts = head("/", &[("x-request-id", "from-client")]);

    to_backend(&mut parts, &forwarding());

    assert_eq!(header(&parts, "x-request-id"), "from-client");
}

#[test]
fn keeps_te_trailers_when_the_client_asked_for_trailers() {
    let mut parts = head("/", &[("te", "trailers")]);

    to_backend(&mut parts, &forwarding());

    assert_eq!(header(&parts, "te"), "trailers");
}

#[test]
fn removes_the_hop_by_hop_headers_of_the_client() {
    let mut parts = head(
        "/",
        &[
            ("connection", "keep-alive, x-internal"),
            ("x-internal", "1"),
            ("keep-alive", "timeout=5"),
            ("proxy-authorization", "Basic Zm9vOmJhcg=="),
            ("upgrade", "h2c"),
            ("accept", "*/*"),
        ],
    );

    to_backend(&mut parts, &forwarding());

    for name in [
        "connection",
        "x-internal",
        "keep-alive",
        "proxy-authorization",
        "upgrade",
    ] {
        assert!(!parts.headers.contains_key(name), "{name}");
    }
    assert!(parts.headers.contains_key("accept"));
}

#[test]
fn a_connection_header_naming_forwarding_headers_strips_what_the_client_sent() {
    // As in v1.1.0, the request is not refused: the headers the client
    // named are stripped, and the request goes on with GFE's own.
    let mut parts = head(
        "/",
        &[
            ("connection", "host, x-forwarded-for, x-request-id"),
            ("host", "a.example.org"),
            ("x-forwarded-for", "198.51.100.1"),
            ("x-request-id", "from-client"),
        ],
    );

    to_backend(&mut parts, &forwarding());

    assert_eq!(header(&parts, "x-forwarded-for"), "192.0.2.7");
    assert_eq!(header(&parts, "x-request-id"), "abc123");
    assert!(!parts.headers.contains_key("host"));
}

#[test]
fn backend_is_told_the_authority_of_the_target() {
    // What an HTTP/2 request looks like: its `:authority` is the target's.
    let mut parts = head("http://Public.example.org:80/x?q=1", &[]);

    to_backend(&mut parts, &forwarding());

    assert_eq!(header(&parts, "host"), "Public.example.org:80");
}

#[test]
fn backend_is_not_told_the_userinfo_of_the_target() {
    let mut parts = head("http://user@a.example.org:8080/x", &[]);

    to_backend(&mut parts, &forwarding());

    assert_eq!(header(&parts, "host"), "a.example.org:8080");
}

#[test]
fn backend_is_told_the_host_header_as_the_client_sent_it() {
    let mut parts = head("/x", &[("host", "a.example.org:8443")]);

    to_backend(&mut parts, &forwarding());

    assert_eq!(header(&parts, "host"), "a.example.org:8443");
}
