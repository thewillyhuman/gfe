use super::*;
use crate::CertStore;

fn resolver() -> Arc<SniResolver> {
    Arc::new(SniResolver::new(CertStore::default()))
}

#[test]
fn advertises_h2_then_http1() {
    let config = server_config(resolver(), MinVersion::Tls12).unwrap();

    assert_eq!(
        config.alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
}

#[test]
fn builds_a_tls13_only_policy() {
    assert!(server_config(resolver(), MinVersion::Tls13).is_ok());
}

#[test]
fn enables_session_tickets() {
    let config = server_config(resolver(), MinVersion::Tls12).unwrap();

    assert!(config.ticketer.enabled());
}
