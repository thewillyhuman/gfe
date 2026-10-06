use super::*;

#[test]
fn dynamic_config_json() {
    let json = r#"{
        "certificates": [{"default": true, "cert_file": "/c.pem", "key_file": "/k.pem"}],
        "listeners": [{"id":"https","address":"0.0.0.0","port":443,"protocol":"https"}],
        "routes": [{"id":"r","listener":"https","host":"a.example.org","action":{"forward":"p"}}],
        "pools": [{"id":"p","scheme":"https","upstreams":[{"host":"10.0.0.1","port":8443}]}]
    }"#;
    let cfg: DynamicConfig = serde_json::from_str(json).unwrap();
    assert_eq!(cfg.certificates.len(), 1);
    assert_eq!(cfg.listeners.len(), 1);
    assert_eq!(cfg.routes.len(), 1);
    assert_eq!(cfg.pools.len(), 1);
}

#[test]
fn rejects_an_unknown_key() {
    let err = serde_json::from_str::<DynamicConfig>(r#"{"listners":[]}"#).unwrap_err();
    assert!(err.to_string().contains("listners"), "{err}");
}
