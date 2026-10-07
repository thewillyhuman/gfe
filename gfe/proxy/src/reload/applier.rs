//! Compiling a dynamic config into what the proxy serves from, and swapping
//! it in. Requests already routed finish against what they started with.

use crate::handler::State;
use crate::metrics::SniLabel;
use crate::reload::ReloadError;
use crate::routing::RouteTable;
use gfe_config::{CertEntry, DynamicConfig, LbPolicy, Scheme, UpstreamPool, validate};
use netkit_health_checking::HealthMap;
use netkit_load_balancing::{Backend, Policy, PoolSet, PoolSpec};
use netkit_tls::{CertSpec, CertStore};
use std::time::{SystemTime, UNIX_EPOCH};

/// A dynamic config validated and compiled into what the proxy serves from,
/// but not serving yet: everything that can make a config unusable, short
/// of binding its listeners, has been checked, and nothing has been swapped
/// in.
pub struct Prepared {
    certificates: CertStore,
    routes: RouteTable,
    pools: PoolSet<Scheme>,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared")
            .field("certificates", &self.certificates.len())
            .field("routes", &self.routes.route_count())
            .field("pools", &self.pools.len())
            .finish()
    }
}

/// Do everything a reload does short of binding listeners and swapping
/// anything in: validate the config, load its certificates, compile its
/// routes and build its pools, which read their backends' health from
/// `health` from then on (a backend it does not know yet is entered as
/// unknown; that is all `prepare` touches).
///
/// A config this accepts is one a reload accepts unless one of its
/// listeners cannot be bound, so it is what `gfe-node --check-config` runs,
/// and what a node runs before it touches any listening socket.
pub fn prepare(config: &DynamicConfig, health: &HealthMap) -> Result<Prepared, ReloadError> {
    validate(config)?;
    Ok(Prepared {
        certificates: CertStore::build(&cert_specs(&config.certificates))?,
        routes: RouteTable::compile(config),
        pools: PoolSet::build(&pool_specs(&config.pools), health)?,
    })
}

/// The certificates of the dynamic config, as the TLS library takes them.
pub(crate) fn cert_specs(entries: &[CertEntry]) -> Vec<CertSpec> {
    entries
        .iter()
        .map(|entry| CertSpec {
            sni: entry.sni.clone(),
            default: entry.default,
            cert_file: entry.cert_file.clone(),
            key_file: entry.key_file.clone(),
        })
        .collect()
}

/// The pools of the dynamic config, as the load-balancing library takes
/// them. Each carries its scheme, which the proxy reads back when it
/// connects to the backend selected.
pub(crate) fn pool_specs(pools: &[UpstreamPool]) -> Vec<PoolSpec<Scheme>> {
    pools
        .iter()
        .map(|pool| PoolSpec {
            id: pool.id.0.clone(),
            policy: match pool.lb_policy {
                LbPolicy::RoundRobin => Policy::RoundRobin,
                LbPolicy::LeastRequest => Policy::LeastRequest,
                LbPolicy::RingHash => Policy::RingHash,
            },
            backends: pool
                .upstreams
                .iter()
                .map(|upstream| Backend {
                    host: upstream.host.clone(),
                    port: upstream.port,
                    weight: upstream.weight,
                })
                .collect(),
            max_in_flight: pool.max_in_flight,
            payload: pool.scheme,
        })
        .collect()
}

/// Swap a prepared config in; it cannot fail. Also forgets the health of
/// backends no longer in any pool, and brings the metrics that describe the
/// config up to date: a certificate that is gone stops exporting its expiry,
/// so that its alert does not fire for something no longer served.
pub(crate) fn install(state: &State, prepared: Prepared) {
    let Prepared {
        certificates,
        routes,
        pools,
    } = prepared;

    let backends = pools.all_backends();
    let expiries = certificates.expiries().to_vec();
    let route_count = routes.route_count();
    let pool_count = pools.len();
    let certificate_count = certificates.len();
    let removed_snis: Vec<String> = state
        .resolver()
        .current()
        .expiries()
        .iter()
        .filter(|(sni, _)| !expiries.iter().any(|(kept, _)| kept == sni))
        .map(|(sni, _)| sni.clone())
        .collect();

    state.resolver().swap(certificates);
    state.swap(routes, pools);
    state.health().retain(&backends);

    let control = &state.metrics().control;
    control
        .active_routes
        .set(i64::try_from(route_count).unwrap_or(i64::MAX));
    control
        .active_pools
        .set(i64::try_from(pool_count).unwrap_or(i64::MAX));
    for (sni, not_after) in expiries {
        control
            .cert_expiry_timestamp
            .get_or_create(&SniLabel { sni })
            .set(not_after);
    }
    for sni in removed_snis {
        control.cert_expiry_timestamp.remove(&SniLabel { sni });
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        });
    control.config_last_reload_timestamp.set(now);

    tracing::info!(
        routes = route_count,
        pools = pool_count,
        certificates = certificate_count,
        "applied dynamic config"
    );
}

#[cfg(test)]
#[path = "applier_test.rs"]
mod tests;
