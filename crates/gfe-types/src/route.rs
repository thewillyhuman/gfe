use crate::listener::ListenerId;
use serde::{Deserialize, Serialize};

/// Unique identifier for a route.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RouteId(pub String);

impl std::fmt::Display for RouteId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A routing rule: match an incoming request and decide what to do with it.
///
/// Matching precedence is resolved by the compiled route table in
/// `gfe-router`: exact host beats wildcard host, and within a host the
/// longest matching path prefix (or an exact path) wins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub id: RouteId,
    /// Which listener this route applies to.
    pub listener: ListenerId,
    /// Host match: an exact name (`api.example.org`), a single-label
    /// wildcard (`*.example.org`), or `*` for any host.
    pub host: String,
    /// Path prefix match (`/`, `/api/`). Defaults to `/` (match all).
    #[serde(default = "default_path_prefix")]
    pub path_prefix: String,
    /// What to do with a matching request.
    pub action: RouteAction,
}

fn default_path_prefix() -> String {
    "/".to_string()
}

/// The action taken when a route matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteAction {
    /// Forward to the named upstream pool.
    Forward(String),
    /// Respond with a redirect (e.g. HTTP→HTTPS).
    Redirect(RedirectAction),
    /// Respond with a fixed status and no upstream call.
    Fixed(FixedAction),
}

/// A redirect response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedirectAction {
    /// Target scheme (`https` is the common case for HTTP→HTTPS redirects).
    pub scheme: String,
    /// Redirect status code (301, 302, 307, 308). Defaults to 308.
    #[serde(default = "default_redirect_status")]
    pub status: u16,
}

fn default_redirect_status() -> u16 {
    308
}

/// A fixed-status response with no upstream call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedAction {
    pub status: u16,
    #[serde(default)]
    pub body: String,
}

#[cfg(test)]
mod tests {
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
}
