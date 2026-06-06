//! Validation run before a revision is created (spec §5). Two layers:
//!
//! 1. **Node-identical semantic validation** by calling `gfe_config::validate`
//!    on the rendered dynamic config, so the controller rejects exactly what a
//!    node would reject on reload.
//! 2. **Controller-only checks** the node cannot make: certificate expiry
//!    (refuse to ship already-expired certs) and SNI coverage (warn when an
//!    HTTPS route's host matches no certificate and no default exists).
//!
//! Errors block a publish; warnings are surfaced but do not.

use gfe_cp_types::FleetState;
use gfe_types::{DynamicConfig, ListenProtocol};
use std::collections::HashSet;
use thiserror::Error;

/// A validation failure that blocks creating a revision.
#[derive(Debug, Error)]
pub enum ValidateError {
    /// The rendered config failed the node's own semantic validation.
    #[error("node validation: {0}")]
    Node(String),
    /// A referenced certificate is already expired.
    #[error("certificate {sha} expired (not_after={not_after}, now={now})")]
    CertExpired {
        sha: String,
        not_after: i64,
        now: i64,
    },
}

/// Outcome of a successful validation: any non-blocking warnings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub warnings: Vec<String>,
}

/// Validate a fleet's desired state and its rendered dynamic config. `now` is
/// unix seconds, used for expiry checks.
pub fn validate(
    state: &FleetState,
    dynamic: &DynamicConfig,
    now: i64,
) -> Result<Report, ValidateError> {
    // Layer 1: node-identical validation.
    gfe_config::validate(dynamic).map_err(|e| ValidateError::Node(e.to_string()))?;

    // Layer 2a: expiry — refuse to roll an already-expired cert.
    for c in &state.certificates {
        if c.not_after > 0 && c.not_after < now {
            return Err(ValidateError::CertExpired {
                sha: c.content_sha.clone(),
                not_after: c.not_after,
                now,
            });
        }
    }

    // Layer 2b: SNI coverage warnings.
    let mut report = Report::default();
    let https: HashSet<&str> = state
        .listeners
        .iter()
        .filter(|l| matches!(l.protocol, ListenProtocol::Https))
        .map(|l| l.name.as_str())
        .collect();
    let has_default = state.certificates.iter().any(|c| c.is_default);

    for r in &state.routes {
        if !https.contains(r.listener.as_str()) || r.host == "*" {
            continue;
        }
        let covered = has_default
            || state
                .certificates
                .iter()
                .any(|c| c.sni.iter().any(|s| sni_matches(s, &r.host)));
        if !covered {
            report.warnings.push(format!(
                "route {} (host {}) on HTTPS listener {} matches no certificate SNI and no default exists",
                r.name, r.host, r.listener
            ));
        }
    }

    Ok(report)
}

/// Whether an SNI pattern (`exact` or `*.suffix`) matches a host. Mirrors the
/// node's single-label wildcard semantics.
fn sni_matches(pattern: &str, host: &str) -> bool {
    if pattern == host {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // `*.example.org` matches exactly one extra leading label.
        if let Some(rest) = host.strip_suffix(suffix) {
            return rest.ends_with('.') && rest[..rest.len() - 1].split('.').count() == 1;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::render_dynamic;
    use gfe_cp_types::{
        Backend, Certificate, Fleet, ListenerSpec, PoolSpec, RouteActionSpec, RouteSpec,
    };
    use gfe_types::{ListenProtocol, Scheme};

    fn base() -> FleetState {
        let mut s = FleetState::new(Fleet::new("f", "10.0.0.1".parse().unwrap()));
        s.listeners.push(ListenerSpec {
            name: "https".into(),
            address: "10.0.0.1".parse().unwrap(),
            port: 443,
            protocol: ListenProtocol::Https,
        });
        s.pools.push(PoolSpec {
            name: "web".into(),
            scheme: Scheme::Http,
            lb_policy: Default::default(),
            health_check: None,
            backends: vec![Backend {
                host: "10.0.0.2".into(),
                port: 8080,
                weight: 1,
                enabled: true,
            }],
        });
        s.routes.push(RouteSpec {
            name: "r".into(),
            listener: "https".into(),
            host: "atlas.example.org".into(),
            path_prefix: "/".into(),
            action: RouteActionSpec::Forward("web".into()),
        });
        s
    }

    fn cert(sni: Vec<&str>, default: bool, not_after: i64) -> Certificate {
        Certificate {
            content_sha: format!("{sni:?}{default}"),
            sni: sni.into_iter().map(String::from).collect(),
            is_default: default,
            not_after,
            created_at: 0,
        }
    }

    #[test]
    fn wildcard_sni_matches_one_label() {
        assert!(sni_matches("*.example.org", "a.example.org"));
        assert!(!sni_matches("*.example.org", "a.b.example.org"));
        assert!(!sni_matches("*.example.org", "example.org"));
        assert!(sni_matches("a.example.org", "a.example.org"));
    }

    #[test]
    fn matching_cert_clears_coverage_warning() {
        let mut s = base();
        s.certificates
            .push(cert(vec!["atlas.example.org"], false, 0));
        let dyn_cfg = render_dynamic(&s);
        let report = validate(&s, &dyn_cfg, 1000).unwrap();
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn uncovered_https_route_warns() {
        let mut s = base();
        s.certificates
            .push(cert(vec!["other.example.org"], false, 0));
        let dyn_cfg = render_dynamic(&s);
        let report = validate(&s, &dyn_cfg, 1000).unwrap();
        assert_eq!(report.warnings.len(), 1);
    }

    #[test]
    fn default_cert_covers_everything() {
        let mut s = base();
        s.certificates.push(cert(vec![], true, 0));
        let dyn_cfg = render_dynamic(&s);
        assert!(validate(&s, &dyn_cfg, 1000).unwrap().warnings.is_empty());
    }

    #[test]
    fn expired_cert_is_refused() {
        let mut s = base();
        s.certificates.push(cert(vec![], true, 500));
        let dyn_cfg = render_dynamic(&s);
        let err = validate(&s, &dyn_cfg, 1000);
        assert!(matches!(err, Err(ValidateError::CertExpired { .. })));
    }

    #[test]
    fn dangling_pool_reference_fails_node_layer() {
        let mut s = base();
        s.certificates.push(cert(vec![], true, 0));
        s.routes[0].action = RouteActionSpec::Forward("missing".into());
        let dyn_cfg = render_dynamic(&s);
        let err = validate(&s, &dyn_cfg, 1000);
        assert!(matches!(err, Err(ValidateError::Node(_))));
    }
}
