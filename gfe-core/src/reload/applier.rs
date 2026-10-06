//! Compiling a dynamic config into what the proxy serves from, and swapping
//! it in. Requests already routed finish against what they started with.

use crate::proxy::State;
use crate::reload::ReloadError;
use crate::routing::RouteTable;
use gfe_config::{DynamicConfig, validate};
use gfe_observability::SniLabel;
use netkit_load_balancing::PoolSet;
use netkit_tls::CertStore;
use std::time::{SystemTime, UNIX_EPOCH};

/// A dynamic config validated and compiled into what the proxy serves from,
/// but not serving yet: everything that can make a config unusable, short
/// of binding its listeners, has been checked, and nothing has been swapped
/// in.
pub struct Prepared {
    certificates: CertStore,
    routes: RouteTable,
    pools: PoolSet,
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
/// routes and build its pools.
///
/// A config this accepts is one a reload accepts unless one of its
/// listeners cannot be bound, so it is what `gfe-node --check-config` runs,
/// and what a node runs before it touches any listening socket.
pub fn prepare(config: &DynamicConfig) -> Result<Prepared, ReloadError> {
    validate(config)?;
    Ok(Prepared {
        certificates: CertStore::build(&config.certificates)?,
        routes: RouteTable::compile(config),
        pools: PoolSet::build(&config.pools)?,
    })
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
