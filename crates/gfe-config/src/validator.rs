//! Semantic validation of the dynamic config, run before any swap so a bad
//! config is rejected wholesale and the running snapshot is kept.

use gfe_types::{DynamicConfig, GfeError, HealthCheckConfig, ListenProtocol, RouteAction};
use std::collections::HashSet;
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::time::Duration;

/// The largest `weight` an upstream may have. Weights are relative, so this
/// leaves ample room for ratios while bounding what a weight costs: the ring
/// of a `ring_hash` pool grows with the weights of its upstreams.
pub const MAX_UPSTREAM_WEIGHT: u32 = 1000;

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
            if u.host.contains(['[', ']']) {
                return Err(GfeError::Validation(format!(
                    "pool {}: upstream host {:?} has brackets; write an IPv6 address \
                     without brackets, e.g. \"2001:db8::1\"",
                    p.id, u.host
                )));
            }
            if u.host.parse::<IpAddr>().is_err() && !is_hostname(&u.host) {
                return Err(GfeError::Validation(format!(
                    "pool {}: upstream host {:?} is neither a hostname nor an IP address \
                     (the port goes in \"port\"; an IPv6 address is written without \
                     brackets, e.g. \"2001:db8::1\")",
                    p.id, u.host
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
        if let Some(check) = &p.health_check {
            validate_health_check(check)
                .map_err(|e| GfeError::Validation(format!("pool {}: health_check.{e}", p.id)))?;
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

/// The shortest health-check `interval`: one probe per backend every 100 ms
/// is already a lot of connections; shorter is a connect storm.
pub const MIN_HEALTH_CHECK_INTERVAL: Duration = Duration::from_millis(100);

/// Validate one health check, a pool's own or the node's defaults. The error
/// starts with the name of the offending field, for the caller to prefix
/// with where the check comes from.
pub fn validate_health_check(check: &HealthCheckConfig) -> Result<(), String> {
    if check.timeout.is_zero() {
        return Err("timeout must be greater than 0s: a zero timeout fails every probe".into());
    }
    if check.interval < MIN_HEALTH_CHECK_INTERVAL {
        return Err(format!(
            "interval must be at least {}ms, got {}ms",
            MIN_HEALTH_CHECK_INTERVAL.as_millis(),
            check.interval.as_millis()
        ));
    }
    if !check.path.starts_with('/') {
        return Err(format!("path must start with '/', got {:?}", check.path));
    }
    if !HTTP_STATUS.contains(&check.expected_status) {
        return Err(format!(
            "expected_status must be an HTTP status (100-599), got {}",
            check.expected_status
        ));
    }
    if let Some(status) = check.drain_status.filter(|s| !HTTP_STATUS.contains(s)) {
        return Err(format!(
            "drain_status must be an HTTP status (100-599), got {status}"
        ));
    }
    Ok(())
}

/// Whether `host` is a DNS hostname: dot-separated labels of 1 to 63
/// letters, digits, hyphens and underscores, not starting or ending with a
/// hyphen, 253 characters at most. Underscores are not in RFC 1123 but
/// resolvers accept them and internal names use them.
fn is_hostname(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// The status codes a backend can answer with.
const HTTP_STATUS: RangeInclusive<u16> = 100..=599;

#[cfg(test)]
mod tests {
    use super::*;
    use gfe_types::{
        CertEntry, HealthCheckConfig, Listener, ListenerId, PoolId, Route, RouteId, Scheme,
        Upstream, UpstreamPool,
    };
    use std::time::Duration;

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
            max_in_flight: None,
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

    /// What `validate` says about a pool whose only upstream is `host`.
    fn validate_upstream_host(host: &str) -> Result<(), GfeError> {
        let mut p = pool("p");
        p.upstreams = vec![backend(host, 1)];
        validate(&config_with_pool(p))
    }

    #[test]
    fn upstream_hostnames_and_ip_literals_pass() {
        for host in [
            "app.example.org",
            "backend-1",
            "10.0.0.1",
            "2001:db8::1",
            "::1",
        ] {
            assert!(validate_upstream_host(host).is_ok(), "{host}");
        }
    }

    #[test]
    fn bracketed_ipv6_upstream_fails_with_how_to_write_it() {
        let err = validate_upstream_host("[2001:db8::1]")
            .unwrap_err()
            .to_string();

        assert!(err.contains("without brackets"), "{err}");
    }

    #[test]
    fn upstream_host_that_is_neither_a_hostname_nor_an_ip_fails() {
        for host in [
            "app example.org",
            "app/x",
            "-app.example.org",
            "app..example.org",
            "10.0.0.1:80",
        ] {
            let err = validate_upstream_host(host).unwrap_err().to_string();

            assert!(err.contains("pool p"), "{host}: {err}");
        }
    }

    /// The error `validate` gives for a pool `p` with the check `check`.
    fn pool_check_error(check: HealthCheckConfig) -> String {
        let mut p = pool("p");
        p.health_check = Some(check);
        validate(&config_with_pool(p)).unwrap_err().to_string()
    }

    #[test]
    fn pool_with_a_valid_health_check_passes() {
        let mut p = pool("p");
        p.health_check = Some(HealthCheckConfig {
            interval: Duration::from_millis(100),
            drain_status: Some(503),
            ..Default::default()
        });

        assert!(validate(&config_with_pool(p)).is_ok());
    }

    #[test]
    fn health_check_with_a_zero_timeout_fails() {
        let err = pool_check_error(HealthCheckConfig {
            timeout: Duration::ZERO,
            ..Default::default()
        });

        assert!(err.contains("pool p: health_check.timeout"), "{err}");
    }

    #[test]
    fn health_check_with_an_interval_below_100ms_fails() {
        let err = pool_check_error(HealthCheckConfig {
            interval: Duration::from_millis(99),
            ..Default::default()
        });

        assert!(err.contains("pool p: health_check.interval"), "{err}");
    }

    #[test]
    fn health_check_with_a_relative_path_fails() {
        let err = pool_check_error(HealthCheckConfig {
            path: "healthz".into(),
            ..Default::default()
        });

        assert!(err.contains("pool p: health_check.path"), "{err}");
    }

    #[test]
    fn health_check_with_an_impossible_expected_status_fails() {
        let err = pool_check_error(HealthCheckConfig {
            expected_status: 600,
            ..Default::default()
        });

        assert!(
            err.contains("pool p: health_check.expected_status"),
            "{err}"
        );
    }

    #[test]
    fn health_check_with_an_impossible_drain_status_fails() {
        let err = pool_check_error(HealthCheckConfig {
            drain_status: Some(99),
            ..Default::default()
        });

        assert!(err.contains("pool p: health_check.drain_status"), "{err}");
    }
}
