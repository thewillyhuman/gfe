//! Semantic validation: whether a config that matches the schema makes
//! sense. A dynamic config is validated before any swap, so a bad one is
//! rejected wholesale and the running snapshot is kept; a bootstrap config
//! is validated as it is loaded, so a node does not start on a bad one.

use crate::{
    ConfigError, DynamicConfig, HealthCheckConfig, ListenProtocol, NodeConfig, RouteAction,
    UpstreamConfig,
};
use std::collections::HashSet;
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::time::Duration;

/// The largest `weight` an upstream may have. Weights are relative, so this
/// leaves ample room for ratios while bounding what a weight costs: the ring
/// of a `ring_hash` pool grows with the weights of its upstreams.
pub const MAX_UPSTREAM_WEIGHT: u32 = 1000;

/// The smallest `limits.max_header_bytes` the HTTP server can be given: it
/// needs at least this much buffer to read a request head.
pub const MIN_HEADER_BYTES: usize = 8192;

/// The shortest health-check `interval`: one probe per backend every 100 ms
/// is already a lot of connections; shorter is a connect storm.
pub const MIN_HEALTH_CHECK_INTERVAL: Duration = Duration::from_millis(100);

/// The status codes a backend can answer with.
const HTTP_STATUS: RangeInclusive<u16> = 100..=599;

/// Validate the dynamic config. Returns the first error found.
pub fn validate(cfg: &DynamicConfig) -> Result<(), ConfigError> {
    validate_dynamic_config(cfg).map_err(ConfigError::InvalidDynamicConfig)
}

fn validate_dynamic_config(cfg: &DynamicConfig) -> Result<(), String> {
    // A node serves nothing without a listener, and applying such a config
    // closes every socket it has. An empty file is far more likely a
    // template that rendered nothing than a wish to stop serving.
    if cfg.listeners.is_empty() {
        return Err(
            "the config has no listeners: a node would close every listening socket; \
             stop the service instead if that is the intent"
                .into(),
        );
    }

    // Unique listener ids, and one listener per address: a listening socket
    // is identified by the address it is bound to.
    let mut listener_ids = HashSet::new();
    let mut listener_addrs = HashSet::new();
    for l in &cfg.listeners {
        if !listener_ids.insert(&l.id.0) {
            return Err(format!("duplicate listener id: {}", l.id));
        }
        if !listener_addrs.insert((l.address, l.port)) {
            return Err(format!(
                "listener {} reuses address {}:{} of another listener",
                l.id, l.address, l.port
            ));
        }
    }

    // Unique pool ids.
    let mut pool_ids = HashSet::new();
    for p in &cfg.pools {
        if !pool_ids.insert(&p.id.0) {
            return Err(format!("duplicate pool id: {}", p.id));
        }
        if p.upstreams.is_empty() {
            return Err(format!("pool {} has no upstreams", p.id));
        }
        for u in &p.upstreams {
            if u.host.is_empty() || u.port == 0 {
                return Err(format!(
                    "pool {} has an invalid upstream {}:{}",
                    p.id, u.host, u.port
                ));
            }
            if u.host.contains(['[', ']']) {
                return Err(format!(
                    "pool {}: upstream host {:?} has brackets; write an IPv6 address \
                     without brackets, e.g. \"2001:db8::1\"",
                    p.id, u.host
                ));
            }
            if u.host.parse::<IpAddr>().is_err() && !is_hostname(&u.host) {
                return Err(format!(
                    "pool {}: upstream host {:?} is neither a hostname nor an IP address \
                     (the port goes in \"port\"; an IPv6 address is written without \
                     brackets, e.g. \"2001:db8::1\")",
                    p.id, u.host
                ));
            }
            if u.weight > MAX_UPSTREAM_WEIGHT {
                return Err(format!(
                    "pool {}: upstream {}:{} has weight {}, above the maximum of \
                     {MAX_UPSTREAM_WEIGHT}; weights are relative, scale them down",
                    p.id, u.host, u.port, u.weight
                ));
            }
        }
        if let Some(check) = &p.health_check {
            validate_health_check(check).map_err(|e| format!("pool {}: health_check.{e}", p.id))?;
        }
    }

    // Unique route ids; references resolve.
    let mut route_ids = HashSet::new();
    for r in &cfg.routes {
        if !route_ids.insert(&r.id.0) {
            return Err(format!("duplicate route id: {}", r.id));
        }
        if !listener_ids.contains(&r.listener.0) {
            return Err(format!(
                "route {} references unknown listener {}",
                r.id, r.listener
            ));
        }
        if let RouteAction::Forward(pool) = &r.action
            && !pool_ids.contains(pool)
        {
            return Err(format!("route {} forwards to unknown pool {}", r.id, pool));
        }
        if r.host.is_empty() {
            return Err(format!("route {} has empty host", r.id));
        }
    }

    // At most one default certificate.
    let defaults = cfg.certificates.iter().filter(|c| c.default).count();
    if defaults > 1 {
        return Err("more than one default certificate".into());
    }

    // An https listener cannot complete a handshake without a certificate.
    let has_https = cfg
        .listeners
        .iter()
        .any(|l| matches!(l.protocol, ListenProtocol::Https));
    if has_https && cfg.certificates.is_empty() {
        return Err("an https listener is configured but no certificates are provided".into());
    }

    Ok(())
}

/// Validate the bootstrap config. The error names the offending key with
/// its section (`limits.max_connections`), for the caller to prefix with the
/// file it comes from.
pub(crate) fn validate_node_config(config: &NodeConfig) -> Result<(), String> {
    if config.limits.max_header_bytes < MIN_HEADER_BYTES {
        return Err(format!(
            "limits.max_header_bytes must be at least {MIN_HEADER_BYTES}, got {}",
            config.limits.max_header_bytes
        ));
    }
    validate_health_check(&config.health_check_defaults)
        .map_err(|e| format!("health_check_defaults.{e}"))?;
    validate_limits_and_timeouts(config)?;
    validate_upstream(&config.upstream)
}

/// Reject a limit or timeout of zero. None of them means "unlimited": a
/// zero limit refuses everything and a zero timeout expires at once.
fn validate_limits_and_timeouts(config: &NodeConfig) -> Result<(), String> {
    let l = &config.limits;
    let limits = [
        ("max_connections", l.max_connections),
        ("max_connections_listener", l.max_connections_listener),
        (
            "max_h2_concurrent_streams",
            l.max_h2_concurrent_streams as usize,
        ),
        ("max_upstream_connections", l.max_upstream_connections),
    ];
    if let Some((name, _)) = limits.iter().find(|(_, value)| *value == 0) {
        return Err(format!(
            "limits.{name} must be greater than 0 (0 is not \"unlimited\": \
             it refuses everything); remove it to use the default"
        ));
    }

    let t = &config.timeouts;
    let timeouts = [
        ("tls_handshake", t.tls_handshake),
        ("request_header", t.request_header),
        ("upstream_connect", t.upstream_connect),
        ("upstream_first_byte", t.upstream_first_byte),
        ("request_total", t.request_total),
        ("client_idle", t.client_idle),
        ("drain_deadline", t.drain_deadline),
    ];
    if let Some((name, _)) = timeouts.iter().find(|(_, value)| value.is_zero()) {
        return Err(format!(
            "timeouts.{name} must be greater than 0s (a zero timeout expires \
             at once); remove it to use the default"
        ));
    }
    Ok(())
}

/// Validate the `[upstream]` section.
fn validate_upstream(upstream: &UpstreamConfig) -> Result<(), String> {
    // Reject half a client identity: without both its certificate and its
    // key the node would silently not present one, and backends requiring
    // mutual TLS would refuse every connection.
    match (&upstream.client_cert_file, &upstream.client_key_file) {
        (Some(_), None) => Err(
            "upstream.client_cert_file is set but upstream.client_key_file is not: \
             set both for mutual TLS, or neither"
                .into(),
        ),
        (None, Some(_)) => Err(
            "upstream.client_key_file is set but upstream.client_cert_file is not: \
             set both for mutual TLS, or neither"
                .into(),
        ),
        _ => Ok(()),
    }
}

/// Validate one health check, a pool's own or the node's defaults. The error
/// starts with the name of the offending field, for the caller to prefix
/// with where the check comes from.
fn validate_health_check(check: &HealthCheckConfig) -> Result<(), String> {
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

#[cfg(test)]
#[path = "validator_test.rs"]
mod tests;
