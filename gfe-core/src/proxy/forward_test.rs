use super::*;

fn request(target: &[u8]) -> RequestHeader {
    RequestHeader::build("GET", target, None).unwrap()
}

fn forwarding(asks_for_trailers: bool) -> Forwarding<'static> {
    Forwarding {
        client: "192.0.2.7".parse().unwrap(),
        proto: "https",
        host: "a.example.org",
        request_id: "abc123",
        asks_for_trailers,
    }
}

fn header<'a>(req: &'a RequestHeader, name: &str) -> &'a str {
    req.headers[name].to_str().unwrap()
}

#[test]
fn adds_the_forwarding_headers() {
    let mut req = request(b"/");

    add_forwarding_headers(&mut req, &forwarding(false)).unwrap();

    assert_eq!(header(&req, "x-forwarded-for"), "192.0.2.7");
    assert_eq!(header(&req, "x-forwarded-proto"), "https");
    assert_eq!(header(&req, "x-forwarded-host"), "a.example.org");
    assert_eq!(
        header(&req, "forwarded"),
        "for=192.0.2.7;host=a.example.org;proto=https"
    );
    assert_eq!(header(&req, "x-request-id"), "abc123");
    assert!(!req.headers.contains_key("te"));
}

#[test]
fn appends_the_client_to_an_existing_x_forwarded_for() {
    let mut req = request(b"/");
    req.insert_header("x-forwarded-for", "198.51.100.1")
        .unwrap();

    add_forwarding_headers(&mut req, &forwarding(false)).unwrap();

    assert_eq!(header(&req, "x-forwarded-for"), "198.51.100.1, 192.0.2.7");
}

#[test]
fn keeps_the_clients_request_id() {
    let mut req = request(b"/");
    req.insert_header("x-request-id", "from-client").unwrap();

    add_forwarding_headers(&mut req, &forwarding(false)).unwrap();

    assert_eq!(header(&req, "x-request-id"), "from-client");
}

#[test]
fn keeps_te_trailers_when_the_client_asked_for_trailers() {
    let mut req = request(b"/");

    add_forwarding_headers(&mut req, &forwarding(true)).unwrap();

    assert_eq!(header(&req, "te"), "trailers");
}

#[test]
fn http1_backend_is_told_the_authority_of_the_target() {
    // What an HTTP/2 request looks like: its `:authority` is the target's.
    let mut req = request(b"/");
    req.set_uri(Uri::from_static("http://Public.example.org:80/x?q=1"));

    set_target_and_host(&mut req, "10.0.0.1:8080").unwrap();

    assert_eq!(header(&req, "host"), "Public.example.org:80");
    assert_eq!(req.uri.to_string(), "/x?q=1");
}

#[test]
fn absolute_form_target_goes_out_in_origin_form() {
    // Pingora keeps the authority of an HTTP/1 absolute-form target out of
    // the URI, and has made sure `Host` names it.
    let mut req = request(b"http://a.example.org:8080/x");
    req.insert_header("host", "a.example.org:8080").unwrap();

    set_target_and_host(&mut req, "10.0.0.1:8080").unwrap();

    assert_eq!(header(&req, "host"), "a.example.org:8080");
    assert_eq!(req.raw_path(), b"/x");
}

#[test]
fn http1_backend_is_told_the_host_header_as_the_client_sent_it() {
    let mut req = request(b"/x");
    req.insert_header("host", "a.example.org:8443").unwrap();

    set_target_and_host(&mut req, "10.0.0.1:8080").unwrap();

    assert_eq!(header(&req, "host"), "a.example.org:8443");
    assert_eq!(req.uri.to_string(), "/x");
}

#[test]
fn http1_request_without_any_host_gets_none() {
    let mut req = request(b"/x");

    set_target_and_host(&mut req, "10.0.0.1:8080").unwrap();

    assert!(!req.headers.contains_key("host"));
}

#[test]
fn http2_backend_is_named_by_its_own_address() {
    let mut req = request(b"/x");
    req.insert_header("host", "a.example.org").unwrap();
    req.set_version(Version::HTTP_2);

    set_target_and_host(&mut req, "10.0.0.1:8080").unwrap();

    assert_eq!(header(&req, "host"), "10.0.0.1:8080");
    assert_eq!(req.uri.to_string(), "/x");
}

#[test]
fn strips_hop_by_hop_and_connection_named_response_headers() {
    let mut resp = ResponseHeader::build(200, None).unwrap();
    resp.insert_header("connection", "x-internal, content-length")
        .unwrap();
    resp.insert_header("x-internal", "1").unwrap();
    resp.insert_header("keep-alive", "timeout=5").unwrap();
    resp.insert_header("content-length", "2").unwrap();
    resp.insert_header("accept-ranges", "bytes").unwrap();

    strip_response_hop_by_hop(&mut resp);

    assert!(!resp.headers.contains_key("x-internal"));
    assert!(!resp.headers.contains_key("keep-alive"));
    assert!(resp.headers.contains_key("content-length"));
    assert!(resp.headers.contains_key("accept-ranges"));
}

#[test]
fn adds_hsts_unless_disabled() {
    let mut resp = ResponseHeader::build(200, None).unwrap();
    add_hsts(&mut resp, "").unwrap();
    assert!(!resp.headers.contains_key("strict-transport-security"));

    add_hsts(&mut resp, "max-age=31536000").unwrap();

    assert_eq!(
        resp.headers["strict-transport-security"],
        "max-age=31536000"
    );
}
