//! The compiled, immutable routing snapshot built from a [`DynamicConfig`].

use crate::matcher::{host_matches, path_prefix_matches};
use gfe_types::{DynamicConfig, ListenerId, Route, RouteAction, RouteId};
use std::collections::HashMap;

/// A single compiled route entry within a host bucket.
#[derive(Debug, Clone)]
pub struct CompiledRoute {
    pub id: RouteId,
    /// The configured host pattern (exact, `*.suffix`, or `*`). Bounded by
    /// config, so it is safe to use as a metric label (unlike the raw `Host`).
    pub host: String,
    pub path_prefix: String,
    pub action: RouteAction,
}

/// Routes for one host pattern, ordered so the longest path prefix wins.
#[derive(Debug, Clone, Default)]
struct HostRoutes {
    /// Sorted by descending `path_prefix` length.
    routes: Vec<CompiledRoute>,
}

impl HostRoutes {
    fn match_path(&self, path: &str) -> Option<&CompiledRoute> {
        self.routes
            .iter()
            .find(|r| path_prefix_matches(&r.path_prefix, path))
    }
}

/// Routes for one listener: exact hosts in a map, wildcard hosts in a list
/// (checked longest-suffix first), and an optional `*` catch-all.
#[derive(Debug, Clone, Default)]
struct ListenerRoutes {
    exact_hosts: HashMap<String, HostRoutes>,
    /// `(pattern, routes)` for `*.suffix` patterns, longest suffix first.
    wildcard_hosts: Vec<(String, HostRoutes)>,
    any_host: HostRoutes,
}

impl ListenerRoutes {
    fn match_request(&self, host: &str, path: &str) -> Option<&CompiledRoute> {
        let host_lc = host.to_ascii_lowercase();
        // 1. exact host
        if let Some(hr) = self.exact_hosts.get(&host_lc) {
            if let Some(r) = hr.match_path(path) {
                return Some(r);
            }
        }
        // 2. wildcard hosts (already ordered longest-suffix first)
        for (pattern, hr) in &self.wildcard_hosts {
            if host_matches(pattern, &host_lc) {
                if let Some(r) = hr.match_path(path) {
                    return Some(r);
                }
            }
        }
        // 3. any-host catch-all
        self.any_host.match_path(path)
    }
}

/// An immutable routing table compiled from the dynamic config. Wrapped in
/// `ArcSwap` by `gfe-config` so the data plane reads it lock-free and the
/// control plane swaps a freshly compiled snapshot atomically.
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    listeners: HashMap<ListenerId, ListenerRoutes>,
    route_count: usize,
}

impl RouteTable {
    /// Compile a route table from the dynamic config.
    pub fn compile(config: &DynamicConfig) -> Self {
        let mut listeners: HashMap<ListenerId, ListenerRoutes> = HashMap::new();
        for route in &config.routes {
            let lr = listeners.entry(route.listener.clone()).or_default();
            insert_route(lr, route);
        }
        // Order each host's routes longest-prefix-first, and the wildcard
        // list longest-suffix-first, so the most specific match wins.
        for lr in listeners.values_mut() {
            for hr in lr.exact_hosts.values_mut() {
                sort_routes(&mut hr.routes);
            }
            for (_, hr) in lr.wildcard_hosts.iter_mut() {
                sort_routes(&mut hr.routes);
            }
            sort_routes(&mut lr.any_host.routes);
            lr.wildcard_hosts.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        }
        RouteTable {
            listeners,
            route_count: config.routes.len(),
        }
    }

    /// Match a request to a route. Returns the most specific compiled route,
    /// or `None` if nothing matches.
    pub fn match_request(
        &self,
        listener: &ListenerId,
        host: &str,
        path: &str,
    ) -> Option<&CompiledRoute> {
        self.listeners
            .get(listener)
            .and_then(|lr| lr.match_request(host, path))
    }

    pub fn route_count(&self) -> usize {
        self.route_count
    }
}

fn insert_route(lr: &mut ListenerRoutes, route: &Route) {
    let compiled = CompiledRoute {
        id: route.id.clone(),
        host: route.host.trim().to_string(),
        path_prefix: route.path_prefix.clone(),
        action: route.action.clone(),
    };
    let host = route.host.trim();
    if host == "*" {
        lr.any_host.routes.push(compiled);
    } else if host.starts_with("*.") {
        let key = host.to_ascii_lowercase();
        match lr.wildcard_hosts.iter_mut().find(|(p, _)| *p == key) {
            Some((_, hr)) => hr.routes.push(compiled),
            None => lr.wildcard_hosts.push((
                key,
                HostRoutes {
                    routes: vec![compiled],
                },
            )),
        }
    } else {
        lr.exact_hosts
            .entry(host.to_ascii_lowercase())
            .or_default()
            .routes
            .push(compiled);
    }
}

fn sort_routes(routes: &mut [CompiledRoute]) {
    routes.sort_by(|a, b| b.path_prefix.len().cmp(&a.path_prefix.len()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use gfe_types::{ListenProtocol, Listener, RouteAction};

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

    #[test]
    fn exact_beats_wildcard() {
        let t = table(vec![
            route("wild", "https", "*.example.org", "/", "wild-pool"),
            route("exact", "https", "api.example.org", "/", "exact-pool"),
        ]);
        let m = t
            .match_request(&ListenerId("https".into()), "api.example.org", "/x")
            .unwrap();
        assert_eq!(m.action, RouteAction::Forward("exact-pool".into()));
    }

    #[test]
    fn longest_path_prefix_wins() {
        let t = table(vec![
            route("root", "https", "a.example.org", "/", "root-pool"),
            route("api", "https", "a.example.org", "/api/", "api-pool"),
        ]);
        let m = t
            .match_request(&ListenerId("https".into()), "a.example.org", "/api/users")
            .unwrap();
        assert_eq!(m.action, RouteAction::Forward("api-pool".into()));
        let m2 = t
            .match_request(&ListenerId("https".into()), "a.example.org", "/other")
            .unwrap();
        assert_eq!(m2.action, RouteAction::Forward("root-pool".into()));
    }

    #[test]
    fn no_match_returns_none() {
        let t = table(vec![route("r", "https", "a.example.org", "/", "p")]);
        assert!(t
            .match_request(&ListenerId("https".into()), "other.org", "/")
            .is_none());
        assert!(t
            .match_request(&ListenerId("http".into()), "a.example.org", "/")
            .is_none());
    }

    #[test]
    fn any_host_catch_all() {
        let t = table(vec![route("any", "https", "*", "/", "default-pool")]);
        let m = t
            .match_request(&ListenerId("https".into()), "whatever.org", "/x")
            .unwrap();
        assert_eq!(m.action, RouteAction::Forward("default-pool".into()));
    }
}
