use super::*;
use crate::policy::hash64;
use netkit_health_checking::HealthStatus;
use std::num::NonZeroU32;

fn pool_with(policy: Policy) -> PoolSpec<()> {
    PoolSpec {
        id: "p".into(),
        policy,
        backends: backends(2, 1),
        max_in_flight: None,
        payload: (),
    }
}

/// `count` backends, `10.0.0.1:80` onwards, each with `weight`.
fn backends(count: u8, weight: u32) -> Vec<Backend> {
    (1..=count)
        .map(|i| Backend {
            host: format!("10.0.0.{i}"),
            port: 80,
            weight,
        })
        .collect()
}

/// The single pool `p` built from `config`, reading `health`.
fn build(config: PoolSpec<()>, health: &HealthMap) -> Arc<Pool<()>> {
    PoolSet::build(&[config], health)
        .unwrap()
        .get("p")
        .unwrap()
        .clone()
}

fn pool_admitting(max_in_flight: Option<u32>) -> Arc<Pool<()>> {
    let mut config = pool_with(Policy::RoundRobin);
    config.max_in_flight = max_in_flight.and_then(NonZeroU32::new);
    build(config, &HealthMap::new(true))
}

const POLICIES: [Policy; 3] = [Policy::RoundRobin, Policy::LeastRequest, Policy::RingHash];

// --- backends -------------------------------------------------------------

#[test]
fn a_backend_authority_is_host_and_port() {
    let backend = Backend {
        host: "backend.example".into(),
        port: 8443,
        weight: 1,
    };

    assert_eq!(backend.authority(), "backend.example:8443");
}

#[test]
fn a_backend_authority_brackets_an_ipv6_literal() {
    let backend = Backend {
        host: "2001:db8::1".into(),
        port: 443,
        weight: 1,
    };

    assert_eq!(backend.authority(), "[2001:db8::1]:443");
}

// --- building -------------------------------------------------------------

#[test]
fn a_pool_hands_back_the_payload_it_was_built_with() {
    let spec = PoolSpec {
        id: "p".into(),
        policy: Policy::RoundRobin,
        backends: backends(1, 1),
        max_in_flight: None,
        payload: "https",
    };

    let set = PoolSet::build(&[spec], &HealthMap::new(true)).unwrap();

    assert_eq!(set.get("p").unwrap().payload(), &"https");
}

#[test]
fn ring_hash_pool_with_too_many_ring_points_is_refused() {
    // 7 backends of weight 1000: 160 x 7000 = 1,120,000 points.
    let mut pool = pool_with(Policy::RingHash);
    pool.backends = backends(7, 1000);

    let err = PoolSet::build(&[pool], &HealthMap::new(true))
        .err()
        .unwrap();

    assert!(matches!(
        &err,
        PoolError::RingTooLarge { pool, points: 1_120_000 } if pool == "p"
    ));
    let message = err.to_string();
    assert!(message.contains("pool p"), "{message}");
    assert!(message.contains("1000000"), "{message}");
}

#[test]
fn ring_hash_pool_with_exactly_the_maximum_of_ring_points_is_built() {
    // 6 x 1000 + 250 = 6250 units of weight: 160 x 6250 = 1,000,000 points.
    let mut pool = pool_with(Policy::RingHash);
    pool.backends = backends(7, 1000);
    pool.backends[6].weight = 250;

    assert!(PoolSet::build(&[pool], &HealthMap::new(true)).is_ok());
}

#[test]
fn round_robin_pool_with_the_same_weights_is_built() {
    let mut pool = pool_with(Policy::RoundRobin);
    pool.backends = backends(7, 1000);

    assert!(PoolSet::build(&[pool], &HealthMap::new(true)).is_ok());
}

#[test]
fn a_pool_set_is_refused_when_one_of_its_pools_is() {
    let mut big = pool_with(Policy::RingHash);
    big.id = "big".into();
    big.backends = backends(7, 1000);

    let err = PoolSet::build(&[pool_with(Policy::RoundRobin), big], &HealthMap::new(true)).err();

    assert!(err.unwrap().to_string().contains("pool big"));
}

#[test]
fn a_pool_set_finds_its_pools_by_id() {
    let mut other = pool_with(Policy::LeastRequest);
    other.id = "q".into();

    let set = PoolSet::build(
        &[pool_with(Policy::RoundRobin), other],
        &HealthMap::new(true),
    )
    .unwrap();

    assert_eq!(set.len(), 2);
    assert!(!set.is_empty());
    assert_eq!(set.get("q").unwrap().policy, Policy::LeastRequest);
    assert!(set.get("missing").is_none());
}

#[test]
fn an_empty_pool_set_is_empty() {
    let set = PoolSet::<()>::build(&[], &HealthMap::new(true)).unwrap();

    assert!(set.is_empty());
    assert_eq!(set.len(), 0);
}

#[test]
fn all_backends_lists_every_backend_of_every_pool() {
    let mut other = pool_with(Policy::RoundRobin);
    other.id = "q".into();
    other.backends = vec![Backend {
        host: "backend.example".into(),
        port: 8443,
        weight: 1,
    }];
    let set = PoolSet::build(
        &[pool_with(Policy::RoundRobin), other],
        &HealthMap::new(true),
    )
    .unwrap();

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
    let h = HealthMap::new(true);
    let p = build(pool_with(Policy::RoundRobin), &h);
    let a = p.select(None).unwrap().backend.host;
    let b = p.select(None).unwrap().backend.host;
    assert_ne!(a, b);
}

#[test]
fn round_robin_with_the_same_weights_visits_each_backend_once_per_cycle() {
    let mut config = pool_with(Policy::RoundRobin);
    config.backends = backends(5, 2);
    let h = HealthMap::new(true);
    let p = build(config, &h);

    for _ in 0..3 {
        let mut cycle: Vec<String> = (0..5)
            .map(|_| p.select(None).unwrap().backend.host)
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
    let mut config = pool_with(Policy::RoundRobin);
    config.backends[0].weight = 1;
    config.backends[1].weight = 3;
    let h = HealthMap::new(true);
    let p = build(config, &h);

    let n = 20_000;
    let b = (0..n)
        .filter(|_| p.select(None).unwrap().backend.host == "10.0.0.2")
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
    let mut config = pool_with(Policy::RoundRobin);
    config.backends = backends(2, 0);
    config.backends.push(Backend {
        host: "10.0.0.3".into(),
        port: 80,
        weight: 1,
    });
    let h = HealthMap::new(true);
    let p = build(config, &h);
    h.set("10.0.0.3", 80, HealthStatus::Unhealthy);

    let a = p.select(None).unwrap().backend.host;
    let b = p.select(None).unwrap().backend.host;

    assert_ne!(a, b);
}

// --- least_request --------------------------------------------------------

#[test]
fn least_request_prefers_idle() {
    let h = HealthMap::new(true);
    let p = build(pool_with(Policy::LeastRequest), &h);
    let first = p.select(None).unwrap();
    let busy = first.backend.host.clone();
    let second = p.select(None).unwrap();
    assert_ne!(second.backend.host, busy);
}

#[test]
fn least_request_counts_a_request_until_its_guard_drops() {
    let h = HealthMap::new(true);
    let p = build(pool_with(Policy::LeastRequest), &h);
    let first = p.select(None).unwrap();
    let second = p.select(None).unwrap();
    let (freed, still_busy) = (first.backend.host.clone(), second.backend.host.clone());

    // Both backends have one in flight; finishing the first request leaves
    // its backend with none, so it is picked next, every time.
    drop(first);
    let third = p.select(None).unwrap();
    assert_eq!(third.backend.host, freed);
    drop(third);
    let fourth = p.select(None).unwrap();
    assert_eq!(fourth.backend.host, freed);
    assert_ne!(fourth.backend.host, still_busy);
}

#[test]
fn least_request_divides_the_load_by_the_weight() {
    let mut config = pool_with(Policy::LeastRequest);
    config.backends[1].weight = 3;
    let h = HealthMap::new(true);
    let p = build(config, &h);

    // Held, never finished: a weight-3 backend takes three requests for every
    // one of a weight-1 backend.
    let held: Vec<Selection> = (0..8).map(|_| p.select(None).unwrap()).collect();

    let on_heavy = held.iter().filter(|s| s.backend.host == "10.0.0.2").count();
    assert_eq!(on_heavy, 6);
}

// --- ring_hash ------------------------------------------------------------

#[test]
fn ring_hash_is_sticky() {
    let h = HealthMap::new(true);
    let p = build(pool_with(Policy::RingHash), &h);
    let key = Some(hash64("client-x"));
    let a = p.select(key).unwrap().backend.host;
    let b = p.select(key).unwrap().backend.host;
    assert_eq!(a, b, "same key sticks to same backend");
}

#[test]
fn ring_hash_falls_to_another_backend_while_the_owner_is_unhealthy_and_back_after() {
    let mut config = pool_with(Policy::RingHash);
    config.backends = backends(5, 1);
    let h = HealthMap::new(true);
    let p = build(config, &h);
    let key = Some(hash64("client-x"));
    let owner = p.select(key).unwrap().backend;

    h.set(&owner.host, owner.port, HealthStatus::Unhealthy);
    let fallback = p.select(key).unwrap().backend;
    assert_ne!(fallback, owner);
    assert_eq!(
        p.select(key).unwrap().backend,
        fallback,
        "the fallback is sticky too"
    );

    h.set(&owner.host, owner.port, HealthStatus::Healthy);
    assert_eq!(p.select(key).unwrap().backend, owner);
}

#[test]
fn ring_hash_without_a_key_selects_a_backend() {
    let h = HealthMap::new(true);
    let p = build(pool_with(Policy::RingHash), &h);

    assert!(p.select(None).is_some());
}

#[test]
fn ring_hash_with_every_weight_zero_falls_back_to_round_robin() {
    let mut config = pool_with(Policy::RingHash);
    config.backends = backends(2, 0);
    let h = HealthMap::new(true);
    let p = build(config, &h);

    let a = p.select(Some(1)).unwrap().backend.host;
    let b = p.select(Some(1)).unwrap().backend.host;

    assert_ne!(a, b);
}

// --- health ---------------------------------------------------------------

#[test]
fn skips_unhealthy() {
    let h = HealthMap::new(true);
    let p = build(pool_with(Policy::RoundRobin), &h);
    h.set("10.0.0.1", 80, HealthStatus::Unhealthy);
    for _ in 0..4 {
        assert_eq!(p.select(None).unwrap().backend.host, "10.0.0.2");
    }
}

#[test]
fn no_policy_selects_an_unhealthy_or_draining_backend() {
    for policy in POLICIES {
        let mut config = pool_with(policy);
        config.backends = backends(3, 1);
        let h = HealthMap::new(true);
        let p = build(config, &h);
        h.set("10.0.0.1", 80, HealthStatus::Unhealthy);
        h.set("10.0.0.2", 80, HealthStatus::Draining);

        for key in 0..50 {
            let host = p.select(Some(hash64(key))).unwrap().backend.host;
            assert_eq!(host, "10.0.0.3", "{policy:?}");
        }
    }
}

#[test]
fn none_when_all_unhealthy() {
    for policy in POLICIES {
        let h = HealthMap::new(true);
        let p = build(pool_with(policy), &h);
        h.set("10.0.0.1", 80, HealthStatus::Unhealthy);
        h.set("10.0.0.2", 80, HealthStatus::Draining);

        assert!(p.select(Some(1)).is_none(), "{policy:?}");
    }
}

#[test]
fn none_when_no_backend_has_been_found_healthy_yet_and_unknown_is_not_trusted() {
    let h = HealthMap::new(false);
    let p = build(pool_with(Policy::RoundRobin), &h);
    assert!(p.select(None).is_none());
}

#[test]
fn none_for_a_pool_without_backends() {
    for policy in POLICIES {
        let mut config = pool_with(policy);
        config.backends.clear();
        let p = build(config, &HealthMap::new(true));

        assert!(p.select(Some(1)).is_none(), "{policy:?}");
    }
}

#[test]
fn a_backend_unhealthy_before_the_pool_is_built_is_skipped() {
    let h = HealthMap::new(true);
    h.set("10.0.0.1", 80, HealthStatus::Unhealthy);
    let p = build(pool_with(Policy::RoundRobin), &h);

    for _ in 0..4 {
        assert_eq!(p.select(None).unwrap().backend.host, "10.0.0.2");
    }
}

#[test]
fn selection_follows_the_health_map_as_it_changes() {
    let h = HealthMap::new(true);
    let p = build(pool_with(Policy::RoundRobin), &h);

    h.set("10.0.0.1", 80, HealthStatus::Unhealthy);
    assert_eq!(p.select(None).unwrap().backend.host, "10.0.0.2");

    h.set("10.0.0.1", 80, HealthStatus::Healthy);
    h.set("10.0.0.2", 80, HealthStatus::Draining);
    assert_eq!(p.select(None).unwrap().backend.host, "10.0.0.1");
}
