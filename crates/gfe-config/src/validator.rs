//! Semantic validation of the dynamic config, run before any swap so a bad
//! config is rejected wholesale and the running snapshot is kept.

use gfe_types::{DynamicConfig, GfeError, LbPolicy, ListenProtocol, RouteAction};
use gfe_upstream::policy::RING_REPLICAS;
use std::collections::HashSet;

/// The largest `weight` an upstream may have. Weights are relative, so this
/// leaves ample room for ratios while bounding what a weight costs: a
/// `ring_hash` pool places `RING_REPLICAS` ring points per unit of weight.
pub const MAX_UPSTREAM_WEIGHT: u32 = 1000;

/// The most points a `ring_hash` pool's ring may hold (`RING_REPLICAS` times
/// the sum of its weights), about 16 MB of ring. Every node builds the ring
/// on every reload and at start, so an unbounded one exhausts memory on the
/// whole fleet at once.
pub const MAX_RING_POINTS: u64 = 1_000_000;

/// Validate the dynamic config. Returns the first error found.
pub fn validate(cfg: &DynamicConfig) -> Result<(), GfeError> {
    // A node serves nothing without a listener, and applying such a config
    // closes every socket it has. An empty file is far more likely a
    // template that rendered nothing than a wish to stop serving.
    if cfg.listeners.is_empty() {
        return Err(GfeError::Validation(
            "the config has no listeners: a node would close every listening socket; \
             stop the service instead if that is the intent"
                .into(),
        ));
    }

    // Unique listener ids, and one listener per address: a listening socket
    // is identified by the address it is bound to.
    let mut listener_ids = HashSet::new();
    let mut listener_addrs = HashSet::new();
    for l in &cfg.listeners {
        if !listener_ids.insert(&l.id.0) {
            return Err(GfeError::Validation(format!(
                "duplicate listener id: {}",
                l.id
            )));
        }
        if !listener_addrs.insert((l.address, l.port)) {
            return Err(GfeError::Validation(format!(
                "listener {} reuses address {}:{} of another listener",
                l.id, l.address, l.port
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
            if u.weight > MAX_UPSTREAM_WEIGHT {
                return Err(GfeError::Validation(format!(
                    "pool {}: upstream {}:{} has weight {}, above the maximum of \
                     {MAX_UPSTREAM_WEIGHT}; weights are relative, scale them down",
                    p.id, u.host, u.port, u.weight
                )));
            }
        }
        if p.lb_policy == LbPolicy::RingHash {
            let weights: u64 = p.upstreams.iter().map(|u| u64::from(u.weight)).sum();
            let points = RING_REPLICAS as u64 * weights;
            if points > MAX_RING_POINTS {
                return Err(GfeError::Validation(format!(
                    "pool {}: its ring_hash ring would hold {points} points \
                     ({RING_REPLICAS} per unit of weight), above the maximum of \
                     {MAX_RING_POINTS}; lower the weights of its upstreams",
                    p.id
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
        CertEntry, LbPolicy, Listener, ListenerId, PoolId, Route, RouteId, Scheme, Upstream,
        UpstreamPool,
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
    fn config_without_listeners_fails() {
        let cfg = DynamicConfig {
            pools: vec![pool("p")],
            ..Default::default()
        };

        let err = validate(&cfg).unwrap_err();

        assert!(err.to_string().contains("no listeners"), "{err}");
    }

    #[test]
    fn two_listeners_on_one_address_fail() {
        let mut second = listener();
        second.id = ListenerId("other".into());
        let cfg = DynamicConfig {
            listeners: vec![listener(), second],
            ..Default::default()
        };

        let err = validate(&cfg).unwrap_err();

        assert!(err.to_string().contains("reuses address"), "{err}");
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
            listeners: vec![listener()],
            ..Default::default()
        };
        let err = validate(&cfg).unwrap_err();
        assert!(err.to_string().contains("default certificate"), "{err}");
    }

    /// A valid config whose only pool is `pool`.
    fn config_with_pool(pool: UpstreamPool) -> DynamicConfig {
        DynamicConfig {
            listeners: vec![listener()],
            pools: vec![pool],
            ..Default::default()
        }
    }

    fn backend(host: &str, weight: u32) -> Upstream {
        Upstream {
            host: host.into(),
            port: 80,
            weight,
        }
    }

    #[test]
    fn upstream_weight_at_the_limit_passes() {
        let mut p = pool("p");
        p.upstreams = vec![backend("10.0.0.1", MAX_UPSTREAM_WEIGHT)];

        assert!(validate(&config_with_pool(p)).is_ok());
    }

    #[test]
    fn upstream_weight_above_the_limit_fails() {
        let mut p = pool("p");
        p.upstreams = vec![backend("10.0.0.1", MAX_UPSTREAM_WEIGHT + 1)];

        let err = validate(&config_with_pool(p)).unwrap_err().to_string();

        assert!(err.contains("pool p"), "{err}");
        assert!(err.contains("1000"), "{err}");
    }

    #[test]
    fn ring_hash_pool_with_too_many_ring_points_fails() {
        // 7 backends at the maximum weight: 160 x 7000 = 1,120,000 points.
        let mut p = pool("p");
        p.lb_policy = LbPolicy::RingHash;
        p.upstreams = (1..=7)
            .map(|i| backend(&format!("10.0.0.{i}"), MAX_UPSTREAM_WEIGHT))
            .collect();

        let err = validate(&config_with_pool(p)).unwrap_err().to_string();

        assert!(err.contains("pool p"), "{err}");
        assert!(err.contains("1000000"), "{err}");
    }

    #[test]
    fn round_robin_pool_with_the_same_weights_passes() {
        let mut p = pool("p");
        p.upstreams = (1..=7)
            .map(|i| backend(&format!("10.0.0.{i}"), MAX_UPSTREAM_WEIGHT))
            .collect();

        assert!(validate(&config_with_pool(p)).is_ok());
    }
}
