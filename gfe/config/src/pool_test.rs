use super::*;

#[test]
fn pool_serde_defaults() {
    let json = r#"{"id":"p","upstreams":[{"host":"10.0.0.1","port":8443}]}"#;
    let p: UpstreamPool = serde_json::from_str(json).unwrap();
    assert_eq!(p.scheme, Scheme::Http);
    assert_eq!(p.lb_policy, LbPolicy::RoundRobin);
    assert_eq!(p.upstreams[0].weight, 1);
    assert_eq!(p.upstreams[0].authority(), "10.0.0.1:8443");
}

fn upstream(host: &str) -> Upstream {
    Upstream {
        host: host.into(),
        port: 8443,
        weight: 1,
    }
}

#[test]
fn authority_of_a_hostname_is_host_colon_port() {
    assert_eq!(
        upstream("app.example.org").authority(),
        "app.example.org:8443"
    );
}

#[test]
fn authority_of_an_ipv6_literal_is_bracketed() {
    assert_eq!(upstream("2001:db8::1").authority(), "[2001:db8::1]:8443");
}

#[test]
fn pool_has_no_in_flight_quota_by_default() {
    let json = r#"{"id":"p","upstreams":[]}"#;
    let p: UpstreamPool = serde_json::from_str(json).unwrap();
    assert_eq!(p.max_in_flight, None);
}

#[test]
fn pool_in_flight_quota_cannot_be_zero() {
    let json = r#"{"id":"p","max_in_flight":0,"upstreams":[]}"#;
    assert!(serde_json::from_str::<UpstreamPool>(json).is_err());
    let json = r#"{"id":"p","max_in_flight":100,"upstreams":[]}"#;
    let p: UpstreamPool = serde_json::from_str(json).unwrap();
    assert_eq!(p.max_in_flight, NonZeroU32::new(100));
}

#[test]
fn pool_has_no_request_rate_by_default() {
    let json = r#"{"id":"p","upstreams":[]}"#;
    let p: UpstreamPool = serde_json::from_str(json).unwrap();
    assert_eq!(p.max_requests_per_second, None);
}

#[test]
fn pool_request_rate_cannot_be_zero() {
    let json = r#"{"id":"p","max_requests_per_second":0,"upstreams":[]}"#;
    assert!(serde_json::from_str::<UpstreamPool>(json).is_err());
    let json = r#"{"id":"p","max_requests_per_second":250,"upstreams":[]}"#;
    let p: UpstreamPool = serde_json::from_str(json).unwrap();
    assert_eq!(p.max_requests_per_second, NonZeroU32::new(250));
}

#[test]
fn pool_scheme_h2c_is_spelled_h2c() {
    let json = r#"{"id":"p","scheme":"h2c","upstreams":[{"host":"10.0.0.1","port":50051}]}"#;
    let p: UpstreamPool = serde_json::from_str(json).unwrap();
    assert_eq!(p.scheme, Scheme::H2c);
}
