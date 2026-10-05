//! The compiled, immutable route table built from a [`DynamicConfig`].

use crate::routing::matcher::{host_matches, path_prefix_matches};
use gfe_config::{DynamicConfig, ListenerId, Route, RouteAction, RouteId};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

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
    routes: Vec<Arc<CompiledRoute>>,
}

impl HostRoutes {
    fn match_path(&self, path: &str) -> Option<&Arc<CompiledRoute>> {
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
    fn match_request(&self, host: &str, path: &str) -> Option<&Arc<CompiledRoute>> {
        // Hosts reach here lowercased already; only lowercase (and allocate)
        // when one does not.
        let host_lc = if host.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(host.to_ascii_lowercase())
        } else {
            Cow::Borrowed(host)
        };
        // 1. exact host
        if let Some(r) = self
            .exact_hosts
            .get(host_lc.as_ref())
            .and_then(|hr| hr.match_path(path))
        {
            return Some(r);
        }
        // 2. wildcard hosts (already ordered longest-suffix first)
        for (pattern, hr) in &self.wildcard_hosts {
            if host_matches(pattern, &host_lc)
                && let Some(r) = hr.match_path(path)
            {
                return Some(r);
            }
        }
        // 3. any-host catch-all
        self.any_host.match_path(path)
    }
}

/// An immutable routing table compiled from the dynamic config. The proxy
/// keeps it behind an `ArcSwap`, so requests read it lock-free and a reload
/// swaps a freshly compiled table in atomically.
///
/// Routes are shared (`Arc`), so that a request can keep the one it matched
/// without holding on to the table.
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
            lr.wildcard_hosts
                .sort_by_key(|entry| std::cmp::Reverse(entry.0.len()));
        }
        RouteTable {
            listeners,
            route_count: config.routes.len(),
        }
    }

    /// Match a request to a route. Returns the most specific compiled route,
    /// or `None` if nothing matches. `host` is compared case-insensitively.
    pub fn match_request(
        &self,
        listener: &ListenerId,
        host: &str,
        path: &str,
    ) -> Option<&Arc<CompiledRoute>> {
        self.listeners
            .get(listener)
            .and_then(|lr| lr.match_request(host, path))
    }

    /// How many routes the table was compiled from.
    pub fn route_count(&self) -> usize {
        self.route_count
    }
}

fn insert_route(lr: &mut ListenerRoutes, route: &Route) {
    let host = route.host.trim();
    let compiled = Arc::new(CompiledRoute {
        id: route.id.clone(),
        host: host.to_string(),
        path_prefix: route.path_prefix.clone(),
        action: route.action.clone(),
    });
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

fn sort_routes(routes: &mut [Arc<CompiledRoute>]) {
    routes.sort_by_key(|r| std::cmp::Reverse(r.path_prefix.len()));
}

#[cfg(test)]
#[path = "table_test.rs"]
mod tests;
