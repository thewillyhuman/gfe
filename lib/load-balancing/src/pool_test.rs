use super::*;
use crate::policy::hash64;
use netkit_health_checking::HealthStatus;
use std::num::NonZeroU32;

fn pool_with(policy: LbPolicy) -> UpstreamPool {
    UpstreamPool {
        id: PoolId("p".into()),
        scheme: Scheme::Http,
        lb_policy: policy,
        upstreams: backends(2, 1),
        health_check: None,
        max_in_flight: None,
    }
}

/// `count` backends, `10.0.0.1:80` onwards, each with `weight`.
fn backends(count: u8, weight: u32) -> Vec<Upstream> {
    (1..=count)
        .map(|i| Upstream {
            host: format!("10.0.0.{i}"),
            port: 80,
            weight,
        })
        .collect()
}

/// The single pool `p` built from `config`.
fn build(config: UpstreamPool) -> Arc<Pool> {
    PoolSet::build(&[config])
        .unwrap()
        .get(&PoolId("p".into()))
        .unwrap()
        .clone()
}

fn pool_admitting(max_in_flight: Option<u32>) -> Arc<Pool> {
    let mut config = pool_with(LbPolicy::RoundRobin);
    config.max_in_flight = max_in_flight.and_then(NonZeroU32::new);
    build(config)
}

const POLICIES: [LbPolicy; 3] = [
    LbPolicy::RoundRobin,
    LbPolicy::LeastRequest,
    LbPolicy::RingHash,
];

// --- building -------------------------------------------------------------

#[test]
fn ring_hash_pool_with_too_many_ring_points_is_refused() {
    // 7 backends of weight 1000: 160 x 7000 = 1,120,000 points.
    let mut pool = pool_with(LbPolicy::RingHash);
    pool.upstreams = backends(7, 1000);

    let err = PoolSet::build(&[pool]).err().unwrap();

    assert!(matches!(
        &err,
        PoolError::RingTooLarge { pool, points: 1_120_000 } if pool.0 == "p"
    ));
    let message = err.to_string();
    assert!(message.contains("pool p"), "{message}");
    assert!(message.contains("1000000"), "{message}");
}

#[test]
fn ring_hash_pool_with_exactly_the_maximum_of_ring_points_is_built() {
    // 6 x 1000 + 250 = 6250 units of weight: 160 x 6250 = 1,000,000 points.
    let mut pool = pool_with(LbPolicy::RingHash);
    pool.upstreams = backends(7, 1000);
    pool.upstreams[6].weight = 250;

    assert!(PoolSet::build(&[pool]).is_ok());
}

#[test]
fn round_robin_pool_with_the_same_weights_is_built() {
    let mut pool = pool_with(LbPolicy::RoundRobin);
    pool.upstreams = backends(7, 1000);

    assert!(PoolSet::build(&[pool]).is_ok());
}

#[test]
fn a_pool_set_is_refused_when_one_of_its_pools_is() {
    let mut big = pool_with(LbPolicy::RingHash);
    big.id = PoolId("big".into());
    big.upstreams = backends(7, 1000);

    let err = PoolSet::build(&[pool_with(LbPolicy::RoundRobin), big]).err();

    assert!(err.unwrap().to_string().contains("pool big"));
}

#[test]
fn a_pool_set_finds_its_pools_by_id() {
    let mut other = pool_with(LbPolicy::LeastRequest);
    other.id = PoolId("q".into());

    let set = PoolSet::build(&[pool_with(LbPolicy::RoundRobin), other]).unwrap();

    assert_eq!(set.len(), 2);
    assert!(!set.is_empty());
    assert_eq!(
        set.get(&PoolId("q".into())).unwrap().policy,
        LbPolicy::LeastRequest
    );
    assert!(set.get(&PoolId("missing".into())).is_none());
}

#[test]
fn an_empty_pool_set_is_empty() {
    let set = PoolSet::build(&[]).unwrap();

    assert!(set.is_empty());
    assert_eq!(set.len(), 0);
}

#[test]
fn all_backends_lists_every_backend_of_every_pool() {
    let mut other = pool_with(LbPolicy::RoundRobin);
    other.id = PoolId("q".into());
    other.upstreams = vec![Upstream {
        host: "backend.example".into(),
        port: 8443,
        weight: 1,
    }];
    let set = PoolSet::build(&[pool_with(LbPolicy::RoundRobin), other]).unwrap();

    let mut all = set.all_backends();
    all.sort();

    assert_eq!(
        all,
        vec![
            ("10.0.0.1".to_string(), 80),
            ("10.0.0.2".to_string(), 80),
            ("backend.example".to_string(), 8443),
        ]
    );
}

// --- admission ------------------------------------------------------------

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
fn a_refused_request_does_not_hold_a_place() {
    let pool = pool_admitting(Some(1));
    let only = pool.admit();
    for _ in 0..10 {
        assert!(pool.admit().is_none());
    }

    drop(only);

    assert!(pool.admit().is_some());
}

#[test]
fn without_max_in_flight_admits_every_request() {
    let pool = pool_admitting(None);

    let admitted: Vec<_> = (0..1000).filter_map(|_| pool.admit()).collect();

    assert_eq!(admitted.len(), 1000);
}

// --- round_robin ----------------------------------------------------------

#[test]
fn round_robin_alternates() {
    let p = build(pool_with(LbPolicy::RoundRobin));
    let h = HealthMap::new(true);
    let a = p.select(&h, None).unwrap().upstream.host;
    let b = p.select(&h, None).unwrap().upstream.host;
    assert_ne!(a, b);
}

#[test]
fn round_robin_with_the_same_weights_visits_each_backend_once_per_cycle() {
    let mut config = pool_with(LbPolicy::RoundRobin);
    config.upstreams = backends(5, 2);
    let p = build(config);
    let h = HealthMap::new(true);

    for _ in 0..3 {
        let mut cycle: Vec<String> = (0..5)
            .map(|_| p.select(&h, None).unwrap().upstream.host)
            .collect();
        cycle.sort();
        assert_eq!(
            cycle,
            ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]
        );
    }
}

#[test]
fn weighted_round_robin_distribution() {
    let mut config = pool_with(LbPolicy::RoundRobin);
    config.upstreams[0].weight = 1;
    config.upstreams[1].weight = 3;
    let p = build(config);
    let h = HealthMap::new(true);

    let n = 20_000;
    let b = (0..n)
        .filter(|_| p.select(&h, None).unwrap().upstream.host == "10.0.0.2")
        .count();

    // Weights 1:3 → ~25% / ~75%; the pick is random, so allow a tolerance
    // far outside what 20,000 draws deviate by.
    let frac_b = b as f64 / n as f64;
    assert!(
        (0.70..0.80).contains(&frac_b),
        "weight 3/4 backend got {frac_b:.3}"
    );
}

#[test]
fn round_robin_with_every_weight_zero_still_selects() {
    let mut config = pool_with(LbPolicy::RoundRobin);
    config.upstreams = backends(2, 0);
    config.upstreams.push(Upstream {
        host: "10.0.0.3".into(),
        port: 80,
        weight: 1,
    });
    let p = build(config);
    let h = HealthMap::new(true);
    h.set("10.0.0.3", 80, HealthStatus::Unhealthy);

    let a = p.select(&h, None).unwrap().upstream.host;
    let b = p.select(&h, None).unwrap().upstream.host;

    assert_ne!(a, b);
}

// --- least_request --------------------------------------------------------

#[test]
fn least_request_prefers_idle() {
    let p = build(pool_with(LbPolicy::LeastRequest));
    let h = HealthMap::new(true);
    let first = p.select(&h, None).unwrap();
    let busy = first.upstream.host.clone();
    let second = p.select(&h, None).unwrap();
    assert_ne!(second.upstream.host, busy);
}

#[test]
fn least_request_counts_a_request_until_its_guard_drops() {
    let p = build(pool_with(LbPolicy::LeastRequest));
    let h = HealthMap::new(true);
    let first = p.select(&h, None).unwrap();
    let second = p.select(&h, None).unwrap();
    let (freed, still_busy) = (first.upstream.host.clone(), second.upstream.host.clone());

    // Both backends have one in flight; finishing the first request leaves
    // its backend with none, so it is picked next, every time.
    drop(first);
    let third = p.select(&h, None).unwrap();
    assert_eq!(third.upstream.host, freed);
    drop(third);
    let fourth = p.select(&h, None).unwrap();
    assert_eq!(fourth.upstream.host, freed);
    assert_ne!(fourth.upstream.host, still_busy);
}

#[test]
fn least_request_divides_the_load_by_the_weight() {
    let mut config = pool_with(LbPolicy::LeastRequest);
    config.upstreams[1].weight = 3;
    let p = build(config);
    let h = HealthMap::new(true);

    // Held, never finished: a weight-3 backend takes three requests for every
    // one of a weight-1 backend.
    let held: Vec<Selection> = (0..8).map(|_| p.select(&h, None).unwrap()).collect();

    let on_heavy = held
        .iter()
        .filter(|s| s.upstream.host == "10.0.0.2")
        .count();
    assert_eq!(on_heavy, 6);
}

// --- ring_hash ------------------------------------------------------------

#[test]
fn ring_hash_is_sticky() {
    let p = build(pool_with(LbPolicy::RingHash));
    let h = HealthMap::new(true);
    let key = Some(hash64("client-x"));
    let a = p.select(&h, key).unwrap().upstream.host;
    let b = p.select(&h, key).unwrap().upstream.host;
    assert_eq!(a, b, "same key sticks to same backend");
}

#[test]
fn ring_hash_falls_to_another_backend_while_the_owner_is_unhealthy_and_back_after() {
    let mut config = pool_with(LbPolicy::RingHash);
    config.upstreams = backends(5, 1);
    let p = build(config);
    let h = HealthMap::new(true);
    let key = Some(hash64("client-x"));
    let owner = p.select(&h, key).unwrap().upstream;

    h.set(&owner.host, owner.port, HealthStatus::Unhealthy);
    let fallback = p.select(&h, key).unwrap().upstream;
    assert_ne!(fallback, owner);
    assert_eq!(
        p.select(&h, key).unwrap().upstream,
        fallback,
        "the fallback is sticky too"
    );

    h.set(&owner.host, owner.port, HealthStatus::Healthy);
    assert_eq!(p.select(&h, key).unwrap().upstream, owner);
}

#[test]
fn ring_hash_without_a_key_selects_a_backend() {
    let p = build(pool_with(LbPolicy::RingHash));
    let h = HealthMap::new(true);

    assert!(p.select(&h, None).is_some());
}

#[test]
fn ring_hash_with_every_weight_zero_falls_back_to_round_robin() {
    let mut config = pool_with(LbPolicy::RingHash);
    config.upstreams = backends(2, 0);
    let p = build(config);
    let h = HealthMap::new(true);

    let a = p.select(&h, Some(1)).unwrap().upstream.host;
    let b = p.select(&h, Some(1)).unwrap().upstream.host;

    assert_ne!(a, b);
}

// --- health ---------------------------------------------------------------

#[test]
fn skips_unhealthy() {
    let p = build(pool_with(LbPolicy::RoundRobin));
    let h = HealthMap::new(true);
    h.set("10.0.0.1", 80, HealthStatus::Unhealthy);
    for _ in 0..4 {
        assert_eq!(p.select(&h, None).unwrap().upstream.host, "10.0.0.2");
    }
}

#[test]
fn no_policy_selects_an_unhealthy_or_draining_backend() {
    for policy in POLICIES {
        let mut config = pool_with(policy);
        config.upstreams = backends(3, 1);
        let p = build(config);
        let h = HealthMap::new(true);
        h.set("10.0.0.1", 80, HealthStatus::Unhealthy);
        h.set("10.0.0.2", 80, HealthStatus::Draining);

        for key in 0..50 {
            let host = p.select(&h, Some(hash64(key))).unwrap().upstream.host;
            assert_eq!(host, "10.0.0.3", "{policy:?}");
        }
    }
}

#[test]
fn none_when_all_unhealthy() {
    for policy in POLICIES {
        let p = build(pool_with(policy));
        let h = HealthMap::new(true);
        h.set("10.0.0.1", 80, HealthStatus::Unhealthy);
        h.set("10.0.0.2", 80, HealthStatus::Draining);

        assert!(p.select(&h, Some(1)).is_none(), "{policy:?}");
    }
}

#[test]
fn none_when_no_backend_has_been_found_healthy_yet_and_unknown_is_not_trusted() {
    let p = build(pool_with(LbPolicy::RoundRobin));
    let h = HealthMap::new(false);
    assert!(p.select(&h, None).is_none());
}

#[test]
fn none_for_a_pool_without_backends() {
    for policy in POLICIES {
        let mut config = pool_with(policy);
        config.upstreams.clear();
        let p = build(config);

        assert!(
            p.select(&HealthMap::new(true), Some(1)).is_none(),
            "{policy:?}"
        );
    }
}

#[test]
fn selection_follows_the_health_map_as_it_changes() {
    let p = build(pool_with(LbPolicy::RoundRobin));
    let h = HealthMap::new(true);

    h.set("10.0.0.1", 80, HealthStatus::Unhealthy);
    assert_eq!(p.select(&h, None).unwrap().upstream.host, "10.0.0.2");

    h.set("10.0.0.1", 80, HealthStatus::Healthy);
    h.set("10.0.0.2", 80, HealthStatus::Draining);
    assert_eq!(p.select(&h, None).unwrap().upstream.host, "10.0.0.1");
}
