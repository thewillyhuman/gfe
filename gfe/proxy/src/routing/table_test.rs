use super::*;
use gfe_config::{ListenProtocol, Listener};

fn listener(id: &str) -> Listener {
    Listener {
        id: ListenerId(id.into()),
        address: "0.0.0.0".parse().unwrap(),
        port: 443,
        protocol: ListenProtocol::Https,
    }
}

fn route(id: &str, listener: &str, host: &str, path: &str, pool: &str) -> Route {
    Route {
        id: RouteId(id.into()),
        listener: ListenerId(listener.into()),
        host: host.into(),
        path_prefix: path.into(),
        action: RouteAction::Forward(pool.into()),
    }
}

fn table(routes: Vec<Route>) -> RouteTable {
    let cfg = DynamicConfig {
        listeners: vec![listener("https")],
        routes,
        ..Default::default()
    };
    RouteTable::compile(&cfg)
}

fn https() -> ListenerId {
    ListenerId("https".into())
}

#[test]
fn exact_host_beats_wildcard() {
    let t = table(vec![
        route("wild", "https", "*.example.org", "/", "wild-pool"),
        route("exact", "https", "api.example.org", "/", "exact-pool"),
    ]);

    let m = t.match_request(&https(), "api.example.org", "/x").unwrap();

    assert_eq!(m.action, RouteAction::Forward("exact-pool".into()));
}

#[test]
fn longest_path_prefix_wins() {
    let t = table(vec![
        route("root", "https", "a.example.org", "/", "root-pool"),
        route("api", "https", "a.example.org", "/api/", "api-pool"),
    ]);

    let api = t
        .match_request(&https(), "a.example.org", "/api/users")
        .unwrap();
    let other = t
        .match_request(&https(), "a.example.org", "/other")
        .unwrap();

    assert_eq!(api.action, RouteAction::Forward("api-pool".into()));
    assert_eq!(other.action, RouteAction::Forward("root-pool".into()));
}

#[test]
fn exact_path_beats_a_shorter_prefix() {
    let t = table(vec![
        route("root", "https", "a.example.org", "/", "root-pool"),
        route("login", "https", "a.example.org", "/login", "login-pool"),
    ]);

    let m = t
        .match_request(&https(), "a.example.org", "/login")
        .unwrap();

    assert_eq!(m.id, RouteId("login".into()));
}

#[test]
fn no_match_returns_none() {
    let t = table(vec![route("r", "https", "a.example.org", "/", "p")]);

    assert!(t.match_request(&https(), "other.org", "/").is_none());
    assert!(
        t.match_request(&ListenerId("http".into()), "a.example.org", "/")
            .is_none()
    );
}

#[test]
fn any_host_catch_all() {
    let t = table(vec![route("any", "https", "*", "/", "default-pool")]);

    let m = t.match_request(&https(), "whatever.org", "/x").unwrap();

    assert_eq!(m.action, RouteAction::Forward("default-pool".into()));
}

#[test]
fn host_is_matched_case_insensitively() {
    let t = table(vec![route("r", "https", "A.example.org", "/", "p")]);

    assert!(t.match_request(&https(), "a.EXAMPLE.org", "/").is_some());
}

#[test]
fn keeps_the_configured_host_pattern() {
    let t = table(vec![route("r", "https", " *.Example.org ", "/", "p")]);

    let m = t.match_request(&https(), "a.example.org", "/").unwrap();

    assert_eq!(m.host, "*.Example.org");
}

#[test]
fn counts_its_routes() {
    let t = table(vec![
        route("a", "https", "a.example.org", "/", "p"),
        route("b", "https", "b.example.org", "/", "p"),
    ]);

    assert_eq!(t.route_count(), 2);
}
