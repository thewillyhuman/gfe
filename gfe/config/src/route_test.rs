use super::*;

#[test]
fn forward_action_serde() {
    let json = r#"{"id":"r","listener":"https","host":"a.example.org","path_prefix":"/","action":{"forward":"pool-1"}}"#;
    let r: Route = serde_json::from_str(json).unwrap();
    assert_eq!(r.action, RouteAction::Forward("pool-1".into()));
}

#[test]
fn redirect_action_serde() {
    let json = r#"{"id":"r","listener":"http","host":"*","action":{"redirect":{"scheme":"https","status":308}}}"#;
    let r: Route = serde_json::from_str(json).unwrap();
    assert_eq!(r.path_prefix, "/");
    assert_eq!(
        r.action,
        RouteAction::Redirect(RedirectAction {
            scheme: "https".into(),
            status: 308
        })
    );
}
