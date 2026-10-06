use super::*;
use http::HeaderValue;
use netkit_tls::CertSpec;

fn host_of(host_header: Option<&str>, uri: &str) -> Result<String, HostError> {
    host_with(host_header, uri, Version::HTTP_11, None)
}

fn host_with(
    host_header: Option<&str>,
    uri: &str,
    version: Version,
    sni: Option<&str>,
) -> Result<String, HostError> {
    let mut headers = HeaderMap::new();
    if let Some(host) = host_header {
        headers.insert(HOST, HeaderValue::from_str(host).unwrap());
    }
    request_host(&uri.parse().unwrap(), &headers, version, sni)
}

#[test]
fn host_from_authority() {
    assert_eq!(
        host_of(None, "http://API.example.org/x"),
        Ok("api.example.org".into())
    );
}

#[test]
fn host_from_header_then_sni() {
    assert_eq!(
        host_of(Some("Host.Example.org:443"), "/path"),
        Ok("host.example.org".into())
    );
    assert_eq!(
        host_with(None, "/path", Version::HTTP_11, Some("sni.example.org")),
        Ok("sni.example.org".into())
    );
}

#[test]
fn authority_and_host_header_naming_the_same_host_agree() {
    assert_eq!(
        host_of(Some("API.example.org"), "http://api.example.org:8080/x"),
        Ok("api.example.org".into())
    );
}

#[test]
fn authority_and_host_header_naming_different_hosts_conflict() {
    assert_eq!(
        host_of(Some("internal.example.org"), "http://public.example.org/"),
        Err(HostError::Conflict {
            target: "public.example.org".into()
        })
    );
}

#[test]
fn authority_and_host_header_naming_different_ports_conflict() {
    assert!(matches!(
        host_of(Some("a.example.org:8443"), "http://a.example.org:443/"),
        Err(HostError::Conflict { .. })
    ));
}

#[test]
fn no_authority_no_host_header_and_no_sni_is_missing() {
    assert_eq!(host_of(None, "/path"), Err(HostError::Missing));
}

#[test]
fn http10_request_without_a_host_is_for_no_host_in_particular() {
    assert_eq!(
        host_with(None, "/path", Version::HTTP_10, None),
        Ok(String::new())
    );
}

#[test]
fn unparseable_host_header_is_missing() {
    assert_eq!(
        host_with(
            Some("a b"),
            "/path",
            Version::HTTP_11,
            Some("sni.example.org")
        ),
        Err(HostError::Missing)
    );
}

#[test]
fn errors_say_how_they_are_answered_and_under_which_host() {
    let misdirected = HostError::Misdirected {
        host: "c.example.org".into(),
    };

    assert_eq!(misdirected.refusal(), Refusal::Misdirected);
    assert_eq!(HostError::Missing.refusal(), Refusal::HostMissing);
    assert_eq!(misdirected.into_host(), "c.example.org");
}

/// One certificate for `a.example.org` and `b.example.org`, another for
/// `c.example.org`.
fn two_certificates() -> CertStore {
    // Each call writes files of its own: tests run in parallel.
    static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let call = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir();
    let mut entries = Vec::new();
    for names in [
        vec!["a.example.org", "b.example.org"],
        vec!["c.example.org"],
    ] {
        let names: Vec<String> = names.into_iter().map(String::from).collect();
        let cert = rcgen::generate_simple_self_signed(names.clone()).unwrap();
        let tag = format!("gfe-core-host-{}-{call}-{}", std::process::id(), names[0]);
        let cert_file = dir.join(format!("{tag}.crt"));
        let key_file = dir.join(format!("{tag}.key"));
        std::fs::write(&cert_file, cert.cert.pem()).unwrap();
        std::fs::write(&key_file, cert.key_pair.serialize_pem()).unwrap();
        entries.push(CertSpec {
            sni: names,
            default: false,
            cert_file,
            key_file,
        });
    }
    CertStore::build(&entries).unwrap()
}

#[test]
fn serves_the_host_of_the_sni() {
    let store = two_certificates();

    let host = covered_by_sni(Some("a.example.org"), "a.example.org".into(), &store);

    assert_eq!(host, Ok("a.example.org".into()));
}

#[test]
fn serves_a_host_covered_by_the_certificate_of_the_sni() {
    let store = two_certificates();

    let host = covered_by_sni(Some("a.example.org"), "b.example.org".into(), &store);

    assert_eq!(host, Ok("b.example.org".into()));
}

#[test]
fn refuses_a_host_covered_by_another_certificate() {
    let store = two_certificates();

    let host = covered_by_sni(Some("a.example.org"), "c.example.org".into(), &store);

    assert_eq!(
        host,
        Err(HostError::Misdirected {
            host: "c.example.org".into()
        })
    );
}

#[test]
fn serves_any_host_without_sni() {
    let host = covered_by_sni(None, "c.example.org".into(), &CertStore::default());

    assert_eq!(host, Ok("c.example.org".into()));
}
