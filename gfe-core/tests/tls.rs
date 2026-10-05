//! TLS termination by a whole front end: which certificate a client gets,
//! a certificate rotated on disk, the TLS policy, session resumption, HSTS,
//! HTTP/2 by ALPN, and the host a connection may ask for.

mod common;

use common::node::{
    Node, eventually, free_port, get_over, h1_tls_client, h2_get_over, listener,
    served_certificate, tls_client, tls_connect,
};
use common::{certificate_files, pool, spawn_h2c_describing_upstream, spawn_upstream};
use gfe_config::{
    CertEntry, DynamicConfig, ListenProtocol, ListenerId, MinVersion, Route, RouteAction, RouteId,
    Scheme,
};
use rustls::pki_types::CertificateDer;
use std::net::SocketAddr;
use std::path::Path;

/// A certificate entry for `names` and the certificate, to trust it by.
fn certificate(names: &[&str], default: bool) -> (CertEntry, CertificateDer<'static>) {
    let (cert_file, key_file, generated) = certificate_files(names);
    let entry = CertEntry {
        sni: if default {
            Vec::new()
        } else {
            names.iter().map(|name| name.to_string()).collect()
        },
        default,
        cert_file,
        key_file,
    };
    (entry, generated.cert.der().clone())
}

/// A route on listener `https` for `host`.
fn https_route(id: &str, host: &str, action: RouteAction) -> Route {
    Route {
        id: RouteId(id.into()),
        listener: ListenerId("https".into()),
        host: host.into(),
        path_prefix: "/".into(),
        action,
    }
}

fn fixed_ok() -> RouteAction {
    RouteAction::Fixed(gfe_config::FixedAction {
        status: 200,
        body: "ok".into(),
    })
}

/// An HTTPS listener `https` answering `ok` to every host, serving
/// `certificates`.
fn https_config(certificates: Vec<CertEntry>) -> DynamicConfig {
    DynamicConfig {
        certificates,
        listeners: vec![listener("https", ListenProtocol::Https, 0)],
        routes: vec![https_route("all", "*", fixed_ok())],
        ..Default::default()
    }
}

/// The certificate a client asking for `sni` is served.
async fn certificate_served_for(
    addr: SocketAddr,
    roots: &[CertificateDer<'static>],
    sni: &str,
) -> CertificateDer<'static> {
    let stream = tls_connect(&h1_tls_client(roots), addr, sni).await.unwrap();
    served_certificate(&stream)
}

struct ThreeCertificates {
    config: DynamicConfig,
    exact: CertificateDer<'static>,
    wildcard: CertificateDer<'static>,
    default: CertificateDer<'static>,
}

fn three_certificates() -> ThreeCertificates {
    let (exact_entry, exact) = certificate(&["a.example.org"], false);
    let (wildcard_entry, wildcard) = certificate(&["*.wild.example.org"], false);
    // Its name is not one the store selects it by: only being the default
    // gets it served for `other.example.net`.
    let (default_entry, default) = certificate(&["other.example.net"], true);
    ThreeCertificates {
        config: https_config(vec![exact_entry, wildcard_entry, default_entry]),
        exact,
        wildcard,
        default,
    }
}

#[tokio::test]
async fn serves_the_certificate_of_an_exact_sni() {
    let certs = three_certificates();
    let node = Node::serving("sni-exact", &certs.config);
    let roots = [certs.exact.clone()];

    let served = certificate_served_for(node.addr("https"), &roots, "a.example.org").await;

    assert_eq!(served, certs.exact);
}

#[tokio::test]
async fn serves_the_wildcard_certificate_to_a_subdomain() {
    let certs = three_certificates();
    let node = Node::serving("sni-wildcard", &certs.config);
    let roots = [certs.wildcard.clone()];

    let served = certificate_served_for(node.addr("https"), &roots, "x.wild.example.org").await;

    assert_eq!(served, certs.wildcard);
}

#[tokio::test]
async fn serves_the_default_certificate_to_an_sni_it_has_none_for() {
    let certs = three_certificates();
    let node = Node::serving("sni-default", &certs.config);
    let roots = [certs.default.clone()];

    let served = certificate_served_for(node.addr("https"), &roots, "other.example.net").await;

    assert_eq!(served, certs.default);
}

#[tokio::test]
async fn refuses_and_counts_an_sni_it_has_no_certificate_for_without_a_default() {
    let (entry, cert) = certificate(&["a.example.org"], false);
    let node = Node::serving("sni-none", &https_config(vec![entry]));

    let refused = tls_connect(&h1_tls_client(&[cert]), node.addr("https"), "b.example.org").await;

    assert!(refused.is_err());
    node.wait_for_metric("gfe_tls_sni_no_cert_total 1").await;
}

/// Write a fresh certificate for `name` over `dir/tls.crt` and
/// `dir/tls.key`, the way a rotation does: certificate first, key second.
fn rotate(dir: &Path, name: &str) -> CertificateDer<'static> {
    let generated = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
    std::fs::write(dir.join("tls.crt"), generated.cert.pem()).unwrap();
    std::fs::write(dir.join("tls.key"), generated.key_pair.serialize_pem()).unwrap();
    generated.cert.der().clone()
}

#[tokio::test]
async fn serves_a_certificate_rotated_on_disk_without_dropping_an_established_connection() {
    let dir = common::node::scratch("rotation");
    let original = rotate(&dir, "a.example.org");
    let config = https_config(vec![CertEntry {
        sni: vec!["a.example.org".into()],
        default: true,
        cert_file: dir.join("tls.crt"),
        key_file: dir.join("tls.key"),
    }]);
    common::node::write_config(&dir.join("gfe-dynamic.json"), &config);
    let node = Node::boot(dir.clone(), &common::node::bootstrap(&dir), Vec::new()).unwrap();
    let addr = node.addr("https");
    let established = tls_connect(
        &h1_tls_client(std::slice::from_ref(&original)),
        addr,
        "a.example.org",
    )
    .await
    .unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(established))
            .await
            .unwrap();
    tokio::spawn(conn);

    let rotated = rotate(&dir, "a.example.org");

    let roots = [original, rotated.clone()];
    assert!(
        eventually(async || certificate_served_for(addr, &roots, "a.example.org").await == rotated)
            .await,
        "the rotated certificate was never served"
    );
    let req = http::Request::builder()
        .uri("/")
        .header("host", "a.example.org")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let response = sender.send_request(req).await.unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn a_tls13_only_policy_refuses_a_tls12_client() {
    let (entry, cert) = certificate(&["a.example.org"], true);
    let node = Node::serving_with("tls13", &https_config(vec![entry]), |node| {
        node.tls.min_version = MinVersion::Tls13;
    });
    let roots = [cert];
    let tls12 = tls_client(&roots, &[&rustls::version::TLS12], &[b"http/1.1"]);
    let tls13 = tls_client(&roots, &[&rustls::version::TLS13], &[b"http/1.1"]);

    let refused = tls_connect(&tls12, node.addr("https"), "a.example.org").await;
    let accepted = tls_connect(&tls13, node.addr("https"), "a.example.org").await;

    assert!(refused.is_err());
    let accepted = accepted.unwrap();
    assert_eq!(
        accepted.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
}

#[tokio::test]
async fn resumes_the_session_of_a_returning_client() {
    let (entry, cert) = certificate(&["a.example.org"], true);
    let node = Node::serving("resumption", &https_config(vec![entry]));
    let client = h1_tls_client(&[cert]);
    let addr = node.addr("https");
    // TLS 1.3 tickets arrive after the handshake: a request reads them.
    let first = tls_connect(&client, addr, "a.example.org").await.unwrap();
    assert_eq!(get_over(first, "a.example.org", "/").await.status, 200);

    let second = tls_connect(&client, addr, "a.example.org").await.unwrap();

    assert_eq!(
        second.get_ref().1.handshake_kind(),
        Some(rustls::HandshakeKind::Resumed)
    );
    assert_eq!(get_over(second, "a.example.org", "/").await.status, 200);
    node.wait_for_metric(r#"resumed="true"} 1"#).await;
    node.wait_for_metric(r#"resumed="false"} 1"#).await;
}

#[tokio::test]
async fn adds_hsts_to_https_responses_only() {
    let upstream = spawn_upstream().await;
    let (entry, cert) = certificate(&["a.example.org"], true);
    let forward = RouteAction::Forward("pool".into());
    let config = DynamicConfig {
        certificates: vec![entry],
        listeners: vec![
            listener("https", ListenProtocol::Https, 0),
            listener("http", ListenProtocol::Http, free_port()),
        ],
        routes: vec![
            https_route("secure", "a.example.org", forward.clone()),
            common::route("plain", "a.example.org", "/", forward),
        ],
        pools: vec![pool("pool", Scheme::Http, &[upstream])],
    };
    let node = Node::serving_with("hsts", &config, |node| {
        node.tls.hsts = "max-age=31536000".into();
    });

    let stream = tls_connect(&h1_tls_client(&[cert]), node.addr("https"), "a.example.org")
        .await
        .unwrap();
    let https = get_over(stream, "a.example.org", "/").await;
    let http = common::get_with(node.addr("http"), "a.example.org", "/", &[]).await;

    assert_eq!(https.status, 200);
    assert_eq!(
        https.headers.get("strict-transport-security").unwrap(),
        "max-age=31536000"
    );
    assert_eq!(http.status, 200);
    assert!(!http.headers.contains_key("strict-transport-security"));
}

#[tokio::test]
async fn terminates_tls_and_forwards_over_http1() {
    let upstream = spawn_upstream().await;
    let (entry, cert) = certificate(&["a.example.org"], true);
    let mut config = https_config(vec![entry]);
    config.routes = vec![https_route(
        "web",
        "a.example.org",
        RouteAction::Forward("pool".into()),
    )];
    config.pools = vec![pool("pool", Scheme::Http, &[upstream])];
    let node = Node::serving("terminates", &config);

    let stream = tls_connect(&h1_tls_client(&[cert]), node.addr("https"), "a.example.org")
        .await
        .unwrap();
    let answer = get_over(stream, "a.example.org", "/").await;

    assert_eq!(answer.status, 200);
    assert_eq!(answer.body, "upstream-ok xff=127.0.0.1 host=a.example.org");
}

#[tokio::test]
async fn speaks_http2_negotiated_by_alpn_from_client_to_backend() {
    let upstream = spawn_h2c_describing_upstream().await;
    let (entry, cert) = certificate(&["a.example.org"], true);
    let mut config = https_config(vec![entry]);
    config.routes = vec![https_route(
        "web",
        "a.example.org",
        RouteAction::Forward("pool".into()),
    )];
    config.pools = vec![pool("pool", Scheme::H2c, &[upstream])];
    let node = Node::serving("alpn-h2", &config);
    let client = tls_client(&[cert], rustls::DEFAULT_VERSIONS, &[b"h2", b"http/1.1"]);

    let stream = tls_connect(&client, node.addr("https"), "a.example.org")
        .await
        .unwrap();
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let answer = h2_get_over(stream, "a.example.org", "/").await;

    assert_eq!(answer.status, 200);
    assert!(
        answer.body.starts_with("version=HTTP/2.0"),
        "{}",
        answer.body
    );
}

/// A connection is for the names of the certificate its SNI selected: a
/// request for a host another certificate covers is misdirected.
#[tokio::test]
async fn answers_421_to_a_host_covered_by_another_certificate_than_the_sni() {
    let (a, a_cert) = certificate(&["a.example.org"], false);
    let (b, _) = certificate(&["b.example.org"], false);
    let node = Node::serving("misdirected", &https_config(vec![a, b]));
    let client = h1_tls_client(&[a_cert]);
    let addr = node.addr("https");

    let other = get_over(
        tls_connect(&client, addr, "a.example.org").await.unwrap(),
        "b.example.org",
        "/",
    )
    .await;
    let own = get_over(
        tls_connect(&client, addr, "a.example.org").await.unwrap(),
        "a.example.org",
        "/",
    )
    .await;

    assert_eq!(other.status, 421);
    assert_eq!(own.status, 200);
}

#[tokio::test]
async fn a_plaintext_client_of_an_https_listener_is_refused_and_counted() {
    let (entry, _) = certificate(&["a.example.org"], true);
    let node = Node::serving("plaintext", &https_config(vec![entry]));

    let mut stream = tokio::net::TcpStream::connect(node.addr("https"))
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::write_all(
        &mut stream,
        b"GET / HTTP/1.1\r\nhost: a.example.org\r\n\r\n",
    )
    .await
    .unwrap();
    common::read_until_closed(&mut stream).await;

    node.wait_for_metric("gfe_tls_handshake_failures_total{reason=")
        .await;
}

/// Read one HTTP/1.1 response with a `content-length` off `stream`.
async fn read_response<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> String {
    use tokio::io::AsyncReadExt;

    let mut received = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = stream.read(&mut buf).await.unwrap();
        assert!(n > 0, "the connection ended before the response did");
        received.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&received);
        if let Some(head_end) = text.find("\r\n\r\n") {
            let length = text[..head_end]
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(str::trim)
                        .map(str::to_string)
                })
                .map_or(0, |length| length.parse::<usize>().unwrap());
            if received.len() >= head_end + 4 + length {
                return text.into_owned();
            }
        }
    }
}

/// A client that closes its side of a TLS connection is answered in kind
/// (`close_notify`) before the node closes its own. Without it the client
/// cannot tell an orderly end from a connection cut short, and a client that
/// waits for the answer reports an error.
#[tokio::test]
async fn answers_a_clients_close_notify_with_its_own() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (entry, root) = certificate(&["a.example.org"], false);
    let node = Node::serving("close-notify", &https_config(vec![entry]));
    let mut stream = tls_connect(&h1_tls_client(&[root]), node.addr("https"), "a.example.org")
        .await
        .unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nhost: a.example.org\r\n\r\n")
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    stream.shutdown().await.unwrap();
    let mut rest = Vec::new();
    let ended = stream.read_to_end(&mut rest).await;

    // rustls reports the end of a connection that was not announced by a
    // `close_notify` as an error (`UnexpectedEof`).
    assert!(
        ended.is_ok(),
        "the node closed without close_notify: {ended:?}"
    );
    assert!(rest.is_empty());
}
