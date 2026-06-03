//! Semantic validation of the dynamic config, run before any swap so a bad
//! config is rejected wholesale and the running snapshot is kept.

use gfe_types::{DynamicConfig, GfeError, ListenProtocol, RouteAction};
use std::collections::HashSet;

/// Validate the dynamic config. Returns the first error found.
pub fn validate(cfg: &DynamicConfig) -> Result<(), GfeError> {
    // Unique listener ids.
    let mut listener_ids = HashSet::new();
    for l in &cfg.listeners {
        if !listener_ids.insert(&l.id.0) {
            return Err(GfeError::Validation(format!(
                "duplicate listener id: {}",
                l.id
            )));
        }
    }

    // Unique pool ids.
    let mut pool_ids = HashSet::new();
    for p in &cfg.pools {
        if !pool_ids.insert(p.id.0.clone()) {
            return Err(GfeError::Validation(format!("duplicate pool id: {}", p.id)));
        }
        if p.upstreams.is_empty() {
            return Err(GfeError::Validation(format!(
                "pool {} has no upstreams",
                p.id
            )));
        }
        for u in &p.upstreams {
            if u.host.is_empty() || u.port == 0 {
                return Err(GfeError::Validation(format!(
                    "pool {} has an invalid upstream {}:{}",
                    p.id, u.host, u.port
                )));
            }
        }
    }

    // Unique route ids; references resolve.
    let mut route_ids = HashSet::new();
    for r in &cfg.routes {
        if !route_ids.insert(&r.id.0) {
            return Err(GfeError::Validation(format!(
                "duplicate route id: {}",
                r.id
            )));
        }
        if !listener_ids.contains(&r.listener.0) {
            return Err(GfeError::Validation(format!(
                "route {} references unknown listener {}",
                r.id, r.listener
            )));
        }
        if let RouteAction::Forward(pool) = &r.action {
            if !pool_ids.contains(pool) {
                return Err(GfeError::Validation(format!(
                    "route {} forwards to unknown pool {}",
                    r.id, pool
                )));
            }
        }
        if r.host.is_empty() {
            return Err(GfeError::Validation(format!(
                "route {} has empty host",
                r.id
            )));
        }
    }

    // At most one default certificate.
    let defaults = cfg.certificates.iter().filter(|c| c.default).count();
    if defaults > 1 {
        return Err(GfeError::Validation(
            "more than one default certificate".into(),
        ));
    }

    // Warn (not fail) if an https listener has no certs available at all.
    let has_https = cfg
        .listeners
        .iter()
        .any(|l| matches!(l.protocol, ListenProtocol::Https));
    if has_https && cfg.certificates.is_empty() {
        return Err(GfeError::Validation(
            "an https listener is configured but no certificates are provided".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gfe_types::{
        CertEntry, Listener, ListenerId, PoolId, Route, RouteId, Scheme, Upstream, UpstreamPool,
    };

    fn listener() -> Listener {
        Listener {
            id: ListenerId("https".into()),
            address: "0.0.0.0".parse().unwrap(),
            port: 443,
            protocol: ListenProtocol::Http, // http to avoid cert requirement
        }
    }

    fn pool(id: &str) -> UpstreamPool {
        UpstreamPool {
            id: PoolId(id.into()),
            scheme: Scheme::Http,
            lb_policy: Default::default(),
            upstreams: vec![Upstream {
                host: "10.0.0.1".into(),
                port: 80,
                weight: 1,
            }],
            health_check: None,
        }
    }

    fn route(id: &str, pool: &str) -> Route {
        Route {
            id: RouteId(id.into()),
            listener: ListenerId("https".into()),
            host: "a.example.org".into(),
            path_prefix: "/".into(),
            action: RouteAction::Forward(pool.into()),
        }
    }

    #[test]
    fn valid_config_passes() {
        let cfg = DynamicConfig {
            listeners: vec![listener()],
            pools: vec![pool("p")],
            routes: vec![route("r", "p")],
            ..Default::default()
        };
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn dangling_pool_ref_fails() {
        let cfg = DynamicConfig {
            listeners: vec![listener()],
            pools: vec![pool("p")],
            routes: vec![route("r", "missing")],
            ..Default::default()
        };
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn https_without_certs_fails() {
        let mut l = listener();
        l.protocol = ListenProtocol::Https;
        let cfg = DynamicConfig {
            listeners: vec![l],
            ..Default::default()
        };
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn two_defaults_fail() {
        let mk = || CertEntry {
            sni: vec![],
            default: true,
            cert_file: "/c.pem".into(),
            key_file: "/k.pem".into(),
        };
        let cfg = DynamicConfig {
            certificates: vec![mk(), mk()],
            ..Default::default()
        };
        assert!(validate(&cfg).is_err());
    }
}
