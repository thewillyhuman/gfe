//! Pools of backends: what a caller asks for ([`PoolSpec`], [`Backend`]),
//! the immutable snapshot built from it ([`PoolSet`]), and per-pool
//! selection over the healthy set.

use crate::PoolError;
use crate::policy::{MAX_RING_POINTS, Policy, RING_REPLICAS, build_ring, ring_pick, weighted_pick};
use netkit_health_checking::HealthMap;
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// One backend of a pool: where it is and its share of the requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backend {
    /// A host name or an IP literal (IPv6 without brackets).
    pub host: String,
    /// The port it serves on.
    pub port: u16,
    /// Its share of the requests relative to the other backends of the
    /// pool. A weight of 0 gets requests only under `round_robin` when every
    /// backend weighs 0.
    pub weight: u32,
}

impl Backend {
    /// `host:port`, with an IPv6 literal bracketed (`[2001:db8::1]:443`) as a
    /// URI authority requires. It is also what places the backend on a
    /// `ring_hash` ring, so it must not change for the same backend.
    pub fn authority(&self) -> String {
        if self.host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// What a pool is built from. `payload` is the caller's own data about the
/// pool (how its backends are spoken to, for instance): the pool carries it
/// and never reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSpec<T> {
    /// The pool's id, unique within a [`PoolSet`].
    pub id: String,
    /// How a backend is chosen.
    pub policy: Policy,
    /// The backends, in the caller's order: `least_request` breaks ties by
    /// it.
    pub backends: Vec<Backend>,
    /// The most requests that may be in flight to the pool at once; `None`
    /// admits every request.
    pub max_in_flight: Option<NonZeroU32>,
    /// The caller's data, handed back by [`Pool::payload`].
    pub payload: T,
}

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

/// The result of selecting a backend: the chosen backend plus an in-flight
/// guard the caller holds for the request's duration.
pub struct Selection {
    /// The backend to send the request to.
    pub backend: Backend,
    /// Counts the request against the backend until dropped (a no-op guard
    /// for policies that do not count).
    pub guard: InflightGuard,
}

/// A single pool with its selection state.
pub struct Pool<T> {
    /// The pool's id, as given in its [`PoolSpec`].
    pub id: String,
    /// How a backend is chosen.
    pub policy: Policy,
    /// The backends, in the order given; the in-flight counters and the
    /// ring refer to them by index.
    pub backends: Vec<Backend>,
    /// The caller's data about the pool.
    payload: T,
    /// The round-robin position, shared by every request to the pool.
    counter: AtomicUsize,
    /// In-flight request counters, aligned with `backends` (least_request).
    inflight: Vec<Arc<AtomicUsize>>,
    /// Consistent-hash ring (only built for `ring_hash`).
    ring: Vec<(u64, usize)>,
    /// `true` when all backend weights are equal — lets `round_robin` use the
    /// cheap lock-free atomic counter instead of weighted random.
    uniform_weights: bool,
    /// Requests admitted to the pool and not yet finished. Kept per pool
    /// snapshot: a config reload starts the count afresh, while requests
    /// admitted before it finish against the old one.
    in_flight: Arc<AtomicUsize>,
    /// The most requests that may be in flight to the pool at once.
    max_in_flight: Option<NonZeroU32>,
}

impl<T: Clone> Pool<T> {
    /// Fails if the pool is a `ring_hash` pool whose ring would hold more
    /// than [`MAX_RING_POINTS`] points.
    fn new(p: &PoolSpec<T>) -> Result<Pool<T>, PoolError> {
        let inflight = p
            .backends
            .iter()
            .map(|_| Arc::new(AtomicUsize::new(0)))
            .collect();
        let ring = if p.policy == Policy::RingHash {
            let authorities: Vec<String> = p.backends.iter().map(|b| b.authority()).collect();
            let weights: Vec<u32> = p.backends.iter().map(|b| b.weight).collect();
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
        let first_weight = p.backends.first().map(|b| b.weight).unwrap_or(1);
        let uniform_weights = p.backends.iter().all(|b| b.weight == first_weight);
        Ok(Pool {
            id: p.id.clone(),
            policy: p.policy,
            backends: p.backends.clone(),
            payload: p.payload.clone(),
            counter: AtomicUsize::new(0),
            inflight,
            ring,
            uniform_weights,
            in_flight: Arc::new(AtomicUsize::new(0)),
            max_in_flight: p.max_in_flight,
        })
    }
}

impl<T> Pool<T> {
    /// The caller's data about the pool, as given in its [`PoolSpec`].
    pub fn payload(&self) -> &T {
        &self.payload
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
            .map(|&i| (i, self.backends[i].weight))
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
                    let w = self.backends[i].weight.max(1) as f64;
                    inflight / w
                };
                score(a).total_cmp(&score(b))
            })
            .expect("non-empty")
    }

    fn healthy_indices(&self, health: &HealthMap) -> Vec<usize> {
        (0..self.backends.len())
            .filter(|&i| {
                let b = &self.backends[i];
                health.is_selectable(&b.host, b.port)
            })
            .collect()
    }

    /// Select one healthy backend, or `None` if the pool has none.
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
            Policy::RoundRobin => self.round_robin(&healthy),
            Policy::LeastRequest => self.least_request(&healthy),
            Policy::RingHash => {
                let key = hash_key.unwrap_or(0);
                let healthy_set: std::collections::HashSet<usize> =
                    healthy.iter().copied().collect();
                ring_pick(&self.ring, key, |i| healthy_set.contains(&i))
                    .unwrap_or_else(|| self.round_robin(&healthy))
            }
        };

        // For least_request, increment and hand back a decrementing guard.
        let guard = if self.policy == Policy::LeastRequest {
            self.inflight[idx].fetch_add(1, Ordering::Relaxed);
            InflightGuard(Some(self.inflight[idx].clone()))
        } else {
            InflightGuard(None)
        };

        Some(Selection {
            backend: self.backends[idx].clone(),
            guard,
        })
    }
}

/// An immutable set of pools, swapped whole when the pools change.
pub struct PoolSet<T> {
    pools: HashMap<String, Arc<Pool<T>>>,
}

impl<T> Default for PoolSet<T> {
    fn default() -> Self {
        PoolSet {
            pools: HashMap::new(),
        }
    }
}

impl<T: Clone> PoolSet<T> {
    /// Build a pool set from `pools`. Fails, naming the pool, if one of them
    /// cannot be built: a `ring_hash` pool whose ring would hold more than
    /// [`MAX_RING_POINTS`] points. Of two pools with the same id, the last
    /// one is kept.
    pub fn build(pools: &[PoolSpec<T>]) -> Result<Self, PoolError> {
        let mut map = HashMap::new();
        for p in pools {
            map.insert(p.id.clone(), Arc::new(Pool::new(p)?));
        }
        Ok(PoolSet { pools: map })
    }
}

impl<T> PoolSet<T> {
    /// The pool with this id, if the set has one.
    pub fn get(&self, id: &str) -> Option<&Arc<Pool<T>>> {
        self.pools.get(id)
    }

    /// All `(host, port)` backends across every pool — used to seed and prune
    /// the health map on reload.
    pub fn all_backends(&self) -> Vec<(String, u16)> {
        let mut out = Vec::new();
        for p in self.pools.values() {
            for b in &p.backends {
                out.push((b.host.clone(), b.port));
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
