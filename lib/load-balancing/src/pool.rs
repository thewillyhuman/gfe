//! Upstream pools: the immutable snapshot of pools compiled from the dynamic
//! config, with per-pool selection over the healthy set.

use crate::PoolError;
use crate::policy::{MAX_RING_POINTS, RING_REPLICAS, build_ring, ring_pick, weighted_pick};
use gfe_config::{LbPolicy, PoolId, Scheme, Upstream, UpstreamPool};
use netkit_health_checking::HealthMap;
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Decrements an in-flight counter when dropped: a backend's (for
/// `least_request`), or a pool's (for its `max_in_flight`).
pub struct InflightGuard(Option<Arc<AtomicUsize>>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        if let Some(c) = &self.0 {
            c.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// The result of selecting a backend: the chosen upstream plus an in-flight
/// guard the caller holds for the request's duration.
pub struct Selection {
    /// The backend to send the request to.
    pub upstream: Upstream,
    /// Counts the request against the backend until dropped (a no-op guard
    /// for policies that do not count).
    pub guard: InflightGuard,
}

/// A single pool with its selection state.
pub struct Pool {
    /// The pool's id, as routes refer to it.
    pub id: PoolId,
    /// The scheme of the upstream leg.
    pub scheme: Scheme,
    /// How a backend is chosen.
    pub policy: LbPolicy,
    /// The backends, in config order; the in-flight counters and the ring
    /// refer to them by index.
    pub upstreams: Vec<Upstream>,
    /// The round-robin position, shared by every request to the pool.
    counter: AtomicUsize,
    /// In-flight request counters, aligned with `upstreams` (least_request).
    inflight: Vec<Arc<AtomicUsize>>,
    /// Consistent-hash ring (only built for `ring_hash`).
    ring: Vec<(u64, usize)>,
    /// `true` when all upstream weights are equal — lets `round_robin` use the
    /// cheap lock-free atomic counter instead of weighted random.
    uniform_weights: bool,
    /// Requests admitted to the pool and not yet finished. Kept per pool
    /// snapshot: a config reload starts the count afresh, while requests
    /// admitted before it finish against the old one.
    in_flight: Arc<AtomicUsize>,
    /// The most requests that may be in flight to the pool at once.
    max_in_flight: Option<NonZeroU32>,
}

impl Pool {
    /// Fails if the pool is a `ring_hash` pool whose ring would hold more
    /// than [`MAX_RING_POINTS`] points.
    fn new(p: &UpstreamPool) -> Result<Pool, PoolError> {
        let inflight = p
            .upstreams
            .iter()
            .map(|_| Arc::new(AtomicUsize::new(0)))
            .collect();
        let ring = if p.lb_policy == LbPolicy::RingHash {
            let authorities: Vec<String> = p.upstreams.iter().map(|u| u.authority()).collect();
            let weights: Vec<u32> = p.upstreams.iter().map(|u| u.weight).collect();
            let points = RING_REPLICAS as u64 * weights.iter().map(|w| u64::from(*w)).sum::<u64>();
            if points > MAX_RING_POINTS {
                return Err(PoolError::RingTooLarge {
                    pool: p.id.clone(),
                    points,
                });
            }
            build_ring(&authorities, &weights)
        } else {
            Vec::new()
        };
        let first_weight = p.upstreams.first().map(|u| u.weight).unwrap_or(1);
        let uniform_weights = p.upstreams.iter().all(|u| u.weight == first_weight);
        Ok(Pool {
            id: p.id.clone(),
            scheme: p.scheme,
            policy: p.lb_policy,
            upstreams: p.upstreams.clone(),
            counter: AtomicUsize::new(0),
            inflight,
            ring,
            uniform_weights,
            in_flight: Arc::new(AtomicUsize::new(0)),
            max_in_flight: p.max_in_flight,
        })
    }

    /// Admit one more request to the pool, unless it already has
    /// `max_in_flight` requests in flight; `None` if it does. The request
    /// counts as in flight until the returned guard is dropped. A pool
    /// without `max_in_flight` admits every request.
    pub fn admit(&self) -> Option<InflightGuard> {
        let Some(max) = self.max_in_flight else {
            return Some(InflightGuard(None));
        };
        let already_in_flight = self.in_flight.fetch_add(1, Ordering::Relaxed);
        // Dropping the guard gives the place back.
        let guard = InflightGuard(Some(self.in_flight.clone()));
        (already_in_flight < max.get() as usize).then_some(guard)
    }

    /// Round-robin over the healthy set. Uniform weights → cheap lock-free
    /// atomic counter; non-uniform → lock-free weighted random.
    fn round_robin(&self, healthy: &[usize]) -> usize {
        if self.uniform_weights {
            let n = self.counter.fetch_add(1, Ordering::Relaxed);
            return healthy[n % healthy.len()];
        }
        let candidates: Vec<(usize, u32)> = healthy
            .iter()
            .map(|&i| (i, self.upstreams[i].weight))
            .collect();
        let total: u64 = candidates.iter().map(|(_, w)| *w as u64).sum();
        if total == 0 {
            // All-zero weights → fall back to even round-robin.
            let n = self.counter.fetch_add(1, Ordering::Relaxed);
            return healthy[n % healthy.len()];
        }
        let r = rand::random::<u64>() % total;
        weighted_pick(&candidates, r)
    }

    /// Weighted least-request: minimize (in-flight + 1) / weight.
    fn least_request(&self, healthy: &[usize]) -> usize {
        *healthy
            .iter()
            .min_by(|&&a, &&b| {
                let score = |i: usize| {
                    let inflight = self.inflight[i].load(Ordering::Relaxed) as f64 + 1.0;
                    let w = self.upstreams[i].weight.max(1) as f64;
                    inflight / w
                };
                score(a).total_cmp(&score(b))
            })
            .expect("non-empty")
    }

    fn healthy_indices(&self, health: &HealthMap) -> Vec<usize> {
        (0..self.upstreams.len())
            .filter(|&i| {
                let u = &self.upstreams[i];
                health.is_selectable(&u.host, u.port)
            })
            .collect()
    }

    /// Select one healthy upstream, or `None` if the pool has none.
    ///
    /// `health` is consulted on every call, so a backend that turns
    /// unhealthy or draining stops receiving new requests at once, without a
    /// rebuild of the pool. `hash_key` is the request's affinity key for
    /// `ring_hash` (`None` hashes as 0); the other policies ignore it.
    pub fn select(&self, health: &HealthMap, hash_key: Option<u64>) -> Option<Selection> {
        let healthy = self.healthy_indices(health);
        if healthy.is_empty() {
            return None;
        }

        let idx = match self.policy {
            LbPolicy::RoundRobin => self.round_robin(&healthy),
            LbPolicy::LeastRequest => self.least_request(&healthy),
            LbPolicy::RingHash => {
                let key = hash_key.unwrap_or(0);
                let healthy_set: std::collections::HashSet<usize> =
                    healthy.iter().copied().collect();
                ring_pick(&self.ring, key, |i| healthy_set.contains(&i))
                    .unwrap_or_else(|| self.round_robin(&healthy))
            }
        };

        // For least_request, increment and hand back a decrementing guard.
        let guard = if self.policy == LbPolicy::LeastRequest {
            self.inflight[idx].fetch_add(1, Ordering::Relaxed);
            InflightGuard(Some(self.inflight[idx].clone()))
        } else {
            InflightGuard(None)
        };

        Some(Selection {
            upstream: self.upstreams[idx].clone(),
            guard,
        })
    }
}

/// An immutable set of pools, swapped atomically on config reload.
#[derive(Default)]
pub struct PoolSet {
    pools: HashMap<PoolId, Arc<Pool>>,
}

impl PoolSet {
    /// Build a pool set from the dynamic config's pools. Fails, naming the
    /// pool, if one of them cannot be built: a `ring_hash` pool whose ring
    /// would hold more than [`MAX_RING_POINTS`] points.
    pub fn build(pools: &[UpstreamPool]) -> Result<Self, PoolError> {
        let mut map = HashMap::new();
        for p in pools {
            map.insert(p.id.clone(), Arc::new(Pool::new(p)?));
        }
        Ok(PoolSet { pools: map })
    }

    /// The pool with this id, if the config has one.
    pub fn get(&self, id: &PoolId) -> Option<&Arc<Pool>> {
        self.pools.get(id)
    }

    /// All `(host, port)` backends across every pool — used to seed and prune
    /// the health map on reload.
    pub fn all_backends(&self) -> Vec<(String, u16)> {
        let mut out = Vec::new();
        for p in self.pools.values() {
            for u in &p.upstreams {
                out.push((u.host.clone(), u.port));
            }
        }
        out
    }

    /// How many pools there are.
    pub fn len(&self) -> usize {
        self.pools.len()
    }

    /// Whether there is no pool.
    pub fn is_empty(&self) -> bool {
        self.pools.is_empty()
    }
}

#[cfg(test)]
#[path = "pool_test.rs"]
mod tests;
