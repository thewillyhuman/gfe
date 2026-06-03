//! Load-balancing selection algorithms.
//!
//! - `round_robin`: advance a shared counter modulo the healthy count.
//! - `least_request`: pick the healthy backend with the fewest in-flight
//!   requests (round-robin tie-break).
//! - `ring_hash`: consistent hash on a per-request key for session affinity;
//!   minimal disruption when the backend set changes.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Number of virtual nodes per backend on the hash ring. More replicas →
/// smoother distribution at higher build cost.
pub const RING_REPLICAS: usize = 160;

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
mod tests {
    use super::*;

    #[test]
    fn ring_is_deterministic_and_stable() {
        let backends = vec!["a:1".to_string(), "b:1".to_string(), "c:1".to_string()];
        let ring = build_ring(&backends, &[1, 1, 1]);
        assert_eq!(ring.len(), 3 * RING_REPLICAS);

        let key = hash64("client-1.2.3.4");
        let a = ring_pick(&ring, key, |_| true).unwrap();
        let b = ring_pick(&ring, key, |_| true).unwrap();
        assert_eq!(a, b, "same key → same backend");
    }

    #[test]
    fn ring_scales_vnodes_by_weight() {
        let backends = vec!["a:1".to_string(), "b:1".to_string()];
        let ring = build_ring(&backends, &[1, 3]);
        assert_eq!(ring.len(), RING_REPLICAS + 3 * RING_REPLICAS);
        // Backend 1 (weight 3) should own roughly 3× the ring points.
        let b1 = ring.iter().filter(|(_, i)| *i == 1).count();
        assert_eq!(b1, 3 * RING_REPLICAS);
    }

    #[test]
    fn ring_skips_unhealthy() {
        let backends = vec!["a:1".to_string(), "b:1".to_string()];
        let ring = build_ring(&backends, &[1, 1]);
        let key = hash64("xyz");
        // Force backend 0 unhealthy; must land on 1.
        let pick = ring_pick(&ring, key, |i| i == 1).unwrap();
        assert_eq!(pick, 1);
    }

    #[test]
    fn weighted_pick_respects_boundaries() {
        // candidates: idx0 weight 1, idx1 weight 3 → total 4.
        let c = [(0usize, 1u32), (1usize, 3u32)];
        assert_eq!(weighted_pick(&c, 0), 0);
        assert_eq!(weighted_pick(&c, 1), 1);
        assert_eq!(weighted_pick(&c, 3), 1);
    }
}
