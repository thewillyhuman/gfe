use super::*;

#[test]
fn min_version_serde() {
    assert_eq!(
        serde_json::from_str::<MinVersion>(r#""1.3""#).unwrap(),
        MinVersion::Tls13
    );
}

#[test]
fn tls_policy_defaults_to_tls_1_2_without_hsts_or_shared_ticket_keys() {
    let tls: TlsConfig = toml::from_str("").unwrap();
    assert_eq!(tls.min_version, MinVersion::Tls12);
    assert!(tls.hsts.is_empty());
    assert_eq!(tls.ticket_key_file, None);
}
