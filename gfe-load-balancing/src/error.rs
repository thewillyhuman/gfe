//! What building the pools of a config can fail at.

use crate::policy::{MAX_RING_POINTS, RING_REPLICAS};
use gfe_config::PoolId;
use thiserror::Error;

/// Why a pool could not be built. Each message names the pool at fault and
/// says how to fix it.
#[derive(Debug, Error)]
pub enum PoolError {
    /// A `ring_hash` pool whose ring would hold more than
    /// [`MAX_RING_POINTS`] points.
    #[error(
        "pool {pool}: its ring_hash ring would hold {points} points \
         ({RING_REPLICAS} per unit of weight), above the maximum of \
         {MAX_RING_POINTS}; lower the weights of its upstreams"
    )]
    RingTooLarge { pool: PoolId, points: u64 },
}
