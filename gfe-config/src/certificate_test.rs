use super::*;

#[test]
fn cert_entry_named() {
    let json =
        r#"{"sni":["a.example.org","*.a.example.org"],"cert_file":"/c.pem","key_file":"/k.pem"}"#;
    let c: CertEntry = serde_json::from_str(json).unwrap();
    assert_eq!(c.sni.len(), 2);
    assert!(!c.default);
}

#[test]
fn cert_entry_default() {
    let json = r#"{"default":true,"cert_file":"/c.pem","key_file":"/k.pem"}"#;
    let c: CertEntry = serde_json::from_str(json).unwrap();
    assert!(c.default);
    assert!(c.sni.is_empty());
}
