use super::*;

#[test]
fn listener_serde_round_trip() {
    let json = r#"{"id":"https","address":"188.184.100.10","port":443,"protocol":"https"}"#;
    let l: Listener = serde_json::from_str(json).unwrap();
    assert_eq!(l.id, ListenerId("https".into()));
    assert_eq!(l.port, 443);
    assert!(l.is_tls());
}

#[test]
fn http_listener_does_not_terminate_tls() {
    let json = r#"{"id":"http","address":"0.0.0.0","port":80,"protocol":"http"}"#;
    let l: Listener = serde_json::from_str(json).unwrap();
    assert!(!l.is_tls());
}
