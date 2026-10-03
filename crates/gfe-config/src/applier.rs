//! Compile a validated dynamic config into snapshots and swap them in
//! atomically. In-flight requests finish on the old snapshots.

use crate::validator::validate;
use gfe_metrics::SniLabel;
use gfe_proxy::ProxyShared;
use gfe_router::RouteTable;
use gfe_tls::CertStore;
use gfe_types::{DynamicConfig, GfeError};
use gfe_upstream::PoolSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// A dynamic config validated and compiled into the snapshots the data plane
/// serves from, but not serving yet: everything that can make a config
/// unusable has been checked, nothing has been swapped in.
pub struct Prepared {
    cert_store: CertStore,
    route_table: RouteTable,
    pool_set: PoolSet,
}

/// Do everything [`apply`] does short of swapping anything in: validate the
/// config, load its certificates, compile its routes and build its pools.
///
/// A config this accepts is one `apply` accepts, so it is what
/// `gfe-node --check-config` runs, and what a node runs before it touches
/// any listening socket.
pub fn prepare(cfg: &DynamicConfig) -> Result<Prepared, GfeError> {
    validate(cfg)?;
    Ok(Prepared {
        cert_store: CertStore::build(&cfg.certificates)?,
        route_table: RouteTable::compile(cfg),
        pool_set: PoolSet::build(&cfg.pools),
    })
}

/// Validate and apply a dynamic config to the running shared state.
///
/// Order is: build everything off the hot path (cert store, route table, pool
/// set), then swap each in. If any build step fails, nothing is swapped and
/// the old snapshots remain live.
pub fn apply(shared: &ProxyShared, cfg: &DynamicConfig) -> Result<(), GfeError> {
    install(shared, prepare(cfg)?);
    Ok(())
}

/// Swap a prepared config in; it cannot fail. In-flight requests finish on
/// the old snapshots.
pub fn install(shared: &ProxyShared, prepared: Prepared) {
    let Prepared {
        cert_store,
        route_table,
        pool_set,
    } = prepared;

    let backends = pool_set.all_backends();
    let expiries: Vec<(String, i64)> = cert_store.expiries().to_vec();
    let route_count = route_table.route_count();
    let pool_count = pool_set.len();

    // Swap atomically.
    shared.resolver.swap(cert_store);
    shared.routes.store(Arc::new(route_table));
    shared.pools.store(Arc::new(pool_set));

    // Prune health entries for backends no longer present.
    shared.health.retain(&backends);

    // Update metrics.
    let m = &shared.metrics.control;
    m.active_routes.set(route_count as i64);
    m.active_pools.set(pool_count as i64);
    for (sni, not_after) in expiries {
        m.cert_expiry_timestamp
            .get_or_create(&SniLabel { sni })
            .set(not_after);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    m.config_last_reload_timestamp.set(now);

    tracing::info!(
        routes = route_count,
        pools = pool_count,
        certs = shared.resolver.current().len(),
        "applied dynamic config"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    use gfe_metrics::GfeMetrics;

    use gfe_types::{
        CertEntry, LimitsConfig, ListenProtocol, Listener, ListenerId, PoolId, Route, RouteAction,
        RouteId, Scheme, TimeoutsConfig, TlsConfig, Upstream, UpstreamPool,
    };
    use gfe_upstream::UpstreamClient;
    use std::io::Write;

    fn temp_cert() -> (std::path::PathBuf, std::path::PathBuf) {
        let cert = rcgen::generate_simple_self_signed(vec!["example.org".into()]).unwrap();
        let dir = std::env::temp_dir();
        let cp = dir.join(format!("gfe-ap-{}.crt", std::process::id()));
        let kp = dir.join(format!("gfe-ap-{}.key", std::process::id()));
        std::fs::File::create(&cp)
            .unwrap()
            .write_all(cert.cert.pem().as_bytes())
            .unwrap();
        std::fs::File::create(&kp)
            .unwrap()
            .write_all(cert.key_pair.serialize_pem().as_bytes())
            .unwrap();
        (cp, kp)
    }

    fn shared() -> ProxyShared {
        ProxyShared::new(
            UpstreamClient::new(8).unwrap(),
            Arc::new(GfeMetrics::new()),
            LimitsConfig::default(),
            TimeoutsConfig::default(),
            TlsConfig::default(),
        )
    }

    #[test]
    fn apply_swaps_snapshots() {
        let (cp, kp) = temp_cert();
        let cfg = DynamicConfig {
            certificates: vec![CertEntry {
                sni: vec![],
                default: true,
                cert_file: cp,
                key_file: kp,
            }],
            listeners: vec![Listener {
                id: ListenerId("https".into()),
                address: "0.0.0.0".parse().unwrap(),
                port: 443,
                protocol: ListenProtocol::Https,
            }],
            routes: vec![Route {
                id: RouteId("r".into()),
                listener: ListenerId("https".into()),
                host: "example.org".into(),
                path_prefix: "/".into(),
                action: RouteAction::Forward("p".into()),
            }],
            pools: vec![UpstreamPool {
                id: PoolId("p".into()),
                scheme: Scheme::Http,
                lb_policy: Default::default(),
                upstreams: vec![Upstream {
                    host: "10.0.0.1".into(),
                    port: 80,
                    weight: 1,
                }],
                health_check: None,
            }],
        };

        let s = shared();
        apply(&s, &cfg).unwrap();
        assert_eq!(s.routes.load().route_count(), 1);
        assert_eq!(s.pools.load().len(), 1);
        assert!(s.resolver.current().resolve(None).is_some());
    }

    #[test]
    fn prepare_rejects_a_certificate_that_cannot_be_loaded() {
        let cfg = DynamicConfig {
            certificates: vec![CertEntry {
                sni: vec![],
                default: true,
                cert_file: "/nonexistent/gfe.crt".into(),
                key_file: "/nonexistent/gfe.key".into(),
            }],
            ..Default::default()
        };

        let err = prepare(&cfg)
            .err()
            .expect("the certificate cannot be loaded");

        assert!(err.to_string().contains("/nonexistent/gfe.crt"), "{err}");
    }

    #[test]
    fn prepare_rejects_an_invalid_config() {
        let cfg = DynamicConfig {
            routes: vec![Route {
                id: RouteId("r".into()),
                listener: ListenerId("missing".into()),
                host: "example.org".into(),
                path_prefix: "/".into(),
                action: RouteAction::Forward("p".into()),
            }],
            ..Default::default()
        };

        assert!(prepare(&cfg).is_err());
    }
}
