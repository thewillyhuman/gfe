//! Upstream pools: the immutable snapshot of pools compiled from the dynamic
//! config, with per-pool selection over the healthy set.

use crate::health_map::HealthMap;
use crate::policy::{build_ring, ring_pick, weighted_pick, MAX_RING_POINTS, RING_REPLICAS};
use gfe_core::config::{LbPolicy, PoolId, Scheme, Upstream, UpstreamPool};
use gfe_core::GfeError;
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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
    pub upstream: Upstream,
    pub guard: InflightGuard,
}

/// A single pool with its selection state.
pub struct Pool {
    pub id: PoolId,
    pub scheme: Scheme,
    pub policy: LbPolicy,
    pub upstreams: Vec<Upstream>,
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
    fn new(p: &UpstreamPool) -> Result<Pool, GfeError> {
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
                return Err(GfeError::Validation(format!(
                    "pool {}: its ring_hash ring would hold {points} points \
                     ({RING_REPLICAS} per unit of weight), above the maximum of \
                     {MAX_RING_POINTS}; lower the weights of its upstreams",
                    p.id
                )));
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
    pub fn build(pools: &[UpstreamPool]) -> Result<Self, GfeError> {
        let mut map = HashMap::new();
        for p in pools {
            map.insert(p.id.clone(), Arc::new(Pool::new(p)?));
        }
        Ok(PoolSet { pools: map })
    }

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

    pub fn len(&self) -> usize {
        self.pools.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pools.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gfe_core::config::HealthStatus;

    fn pool_with(policy: LbPolicy) -> UpstreamPool {
        UpstreamPool {
            id: PoolId("p".into()),
            scheme: Scheme::Http,
            lb_policy: policy,
            upstreams: vec![
                Upstream {
                    host: "10.0.0.1".into(),
                    port: 80,
                    weight: 1,
                },
                Upstream {
                    host: "10.0.0.2".into(),
                    port: 80,
                    weight: 1,
                },
            ],
            health_check: None,
            max_in_flight: None,
        }
    }

    /// `count` backends, each with `weight`.
    fn backends(count: u8, weight: u32) -> Vec<Upstream> {
        (1..=count)
            .map(|i| Upstream {
                host: format!("10.0.0.{i}"),
                port: 80,
                weight,
            })
            .collect()
    }

    #[test]
    fn ring_hash_pool_with_too_many_ring_points_is_refused() {
        // 7 backends of weight 1000: 160 x 7000 = 1,120,000 points.
        let mut pool = pool_with(LbPolicy::RingHash);
        pool.upstreams = backends(7, 1000);

        let err = PoolSet::build(&[pool]).err().unwrap().to_string();

        assert!(err.contains("pool p"), "{err}");
        assert!(err.contains("1000000"), "{err}");
    }

    #[test]
    fn round_robin_pool_with_the_same_weights_is_built() {
        let mut pool = pool_with(LbPolicy::RoundRobin);
        pool.upstreams = backends(7, 1000);

        assert!(PoolSet::build(&[pool]).is_ok());
    }

    fn pool_admitting(max_in_flight: Option<u32>) -> Arc<Pool> {
        let mut config = pool_with(LbPolicy::RoundRobin);
        config.max_in_flight = max_in_flight.and_then(std::num::NonZeroU32::new);
        PoolSet::build(&[config])
            .unwrap()
            .get(&PoolId("p".into()))
            .unwrap()
            .clone()
    }

    #[test]
    fn admits_up_to_max_in_flight_and_no_further() {
        let pool = pool_admitting(Some(2));

        let first = pool.admit();
        let second = pool.admit();
        let third = pool.admit();

        assert!(first.is_some() && second.is_some());
        assert!(third.is_none());
    }

    #[test]
    fn a_finished_request_makes_room_again() {
        let pool = pool_admitting(Some(1));
        let only = pool.admit();

        drop(only);

        assert!(pool.admit().is_some());
    }

    #[test]
    fn without_max_in_flight_admits_every_request() {
        let pool = pool_admitting(None);

        let admitted: Vec<_> = (0..1000).filter_map(|_| pool.admit()).collect();

        assert_eq!(admitted.len(), 1000);
    }

    #[test]
    fn round_robin_alternates() {
        let set = PoolSet::build(&[pool_with(LbPolicy::RoundRobin)]).unwrap();
        let p = set.get(&PoolId("p".into())).unwrap();
        let h = HealthMap::new(true);
        let a = p.select(&h, None).unwrap().upstream.host;
        let b = p.select(&h, None).unwrap().upstream.host;
        assert_ne!(a, b);
    }

    #[test]
    fn least_request_prefers_idle() {
        let set = PoolSet::build(&[pool_with(LbPolicy::LeastRequest)]).unwrap();
        let p = set.get(&PoolId("p".into())).unwrap();
        let h = HealthMap::new(true);
        // Hold one request on whatever gets picked first.
        let first = p.select(&h, None).unwrap();
        let busy = first.upstream.host.clone();
        // Next selection should avoid the busy backend.
        let second = p.select(&h, None).unwrap();
        assert_ne!(second.upstream.host, busy);
        drop(first);
        drop(second);
    }

    #[test]
    fn weighted_round_robin_distribution() {
        let pool = UpstreamPool {
            id: PoolId("p".into()),
            scheme: Scheme::Http,
            lb_policy: LbPolicy::RoundRobin,
            upstreams: vec![
                Upstream {
                    host: "a".into(),
                    port: 1,
                    weight: 1,
                },
                Upstream {
                    host: "b".into(),
                    port: 1,
                    weight: 3,
                },
            ],
            health_check: None,
            max_in_flight: None,
        };
        let set = PoolSet::build(&[pool]).unwrap();
        let p = set.get(&PoolId("p".into())).unwrap();
        let h = HealthMap::new(true);

        let mut a = 0;
        let mut b = 0;
        let n = 20_000;
        for _ in 0..n {
            match p.select(&h, None).unwrap().upstream.host.as_str() {
                "a" => a += 1,
                "b" => b += 1,
                _ => unreachable!(),
            }
        }
        // Expect ~25% / ~75% (weights 1:3). Allow generous tolerance.
        let frac_b = b as f64 / n as f64;
        assert!(
            (0.70..0.80).contains(&frac_b),
            "weight 3/4 backend got {frac_b:.3} (a={a}, b={b})"
        );
    }

    #[test]
    fn ring_hash_is_sticky() {
        let set = PoolSet::build(&[pool_with(LbPolicy::RingHash)]).unwrap();
        let p = set.get(&PoolId("p".into())).unwrap();
        let h = HealthMap::new(true);
        let key = Some(crate::policy::hash64("client-x"));
        let a = p.select(&h, key).unwrap().upstream.host;
        let b = p.select(&h, key).unwrap().upstream.host;
        assert_eq!(a, b, "same key sticks to same backend");
    }

    #[test]
    fn skips_unhealthy() {
        let set = PoolSet::build(&[pool_with(LbPolicy::RoundRobin)]).unwrap();
        let p = set.get(&PoolId("p".into())).unwrap();
        let h = HealthMap::new(true);
        h.set("10.0.0.1", 80, HealthStatus::Unhealthy);
        for _ in 0..4 {
            assert_eq!(p.select(&h, None).unwrap().upstream.host, "10.0.0.2");
        }
    }

    #[test]
    fn none_when_all_unhealthy() {
        let set = PoolSet::build(&[pool_with(LbPolicy::RoundRobin)]).unwrap();
        let p = set.get(&PoolId("p".into())).unwrap();
        let h = HealthMap::new(false);
        assert!(p.select(&h, None).is_none());
    }
}
