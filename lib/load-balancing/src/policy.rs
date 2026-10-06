//! Load-balancing selection algorithms.
//!
//! - `round_robin`: advance a shared counter modulo the healthy count when
//!   every backend has the same weight; otherwise a random pick in
//!   proportion to the weights.
//! - `least_request`: pick the healthy backend with the fewest in-flight
//!   requests per unit of weight (the first in the order given on a tie).
//! - `ring_hash`: consistent hash on a per-request key for session affinity;
//!   minimal disruption when the backend set changes.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// How a pool chooses among its healthy backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// In turn, or at random in proportion to the weights when they differ.
    RoundRobin,
    /// The fewest requests in flight per unit of weight.
    LeastRequest,
    /// Consistent hashing of a per-request key, for affinity.
    RingHash,
}

/// Number of virtual nodes per backend on the hash ring. More replicas →
/// smoother distribution at higher build cost.
pub const RING_REPLICAS: usize = 160;

/// The most points a ring may hold (`RING_REPLICAS` times the sum of the
/// weights of its backends), about 16 MB of ring. The ring is built whenever
/// the pools are, so an unbounded one would exhaust the memory of every
/// process built from the same pools at once.
pub const MAX_RING_POINTS: u64 = 1_000_000;

/// Hash a value to a ring point.
pub fn hash64<T: Hash>(v: T) -> u64 {
    let mut h = DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

/// Build a sorted consistent-hash ring of `(point, upstream_index)` from the
/// backend authorities. Each backend gets `RING_REPLICAS × weight` virtual
/// nodes, so a heavier backend owns proportionally more of the keyspace
/// (weighted affinity). A weight of 0 places the backend on no ring points.
pub fn build_ring(authorities: &[String], weights: &[u32]) -> Vec<(u64, usize)> {
    let mut ring = Vec::new();
    for (idx, authority) in authorities.iter().enumerate() {
        let weight = weights.get(idx).copied().unwrap_or(1) as usize;
        let replicas = RING_REPLICAS.saturating_mul(weight);
        for replica in 0..replicas {
            ring.push((hash64((authority, replica)), idx));
        }
    }
    ring.sort_by_key(|(p, _)| *p);
    ring
}

/// Weighted pick: given `(index, weight)` pairs and a random draw `r` in
/// `[0, total_weight)`, return the selected index. Lock-free; O(n).
pub fn weighted_pick(candidates: &[(usize, u32)], r: u64) -> usize {
    let mut acc = 0u64;
    for &(idx, w) in candidates {
        acc += w as u64;
        if r < acc {
            return idx;
        }
    }
    // Fallback (e.g. rounding): last candidate.
    candidates.last().map(|&(i, _)| i).unwrap_or(0)
}

/// Walk the ring from the point at/after `key` and return the first upstream
/// index that is in `healthy` (a sorted-or-unsorted set membership test).
pub fn ring_pick(
    ring: &[(u64, usize)],
    key: u64,
    is_healthy: impl Fn(usize) -> bool,
) -> Option<usize> {
    if ring.is_empty() {
        return None;
    }
    let start = ring.partition_point(|(p, _)| *p < key);
    for off in 0..ring.len() {
        let (_, idx) = ring[(start + off) % ring.len()];
        if is_healthy(idx) {
            return Some(idx);
        }
    }
    None
}

#[cfg(test)]
#[path = "policy_test.rs"]
mod tests;
