use super::*;

/// `count` backend authorities, `10.0.0.1:80` onwards.
fn authorities(count: usize) -> Vec<String> {
    (1..=count).map(|i| format!("10.0.0.{i}:80")).collect()
}

/// The authority that owns each of `keys` on a ring built over `backends`
/// with weight 1 each, everyone healthy.
fn owners(backends: &[String], keys: &[u64]) -> Vec<String> {
    let ring = build_ring(backends, &vec![1; backends.len()]);
    keys.iter()
        .map(|&key| backends[ring_pick(&ring, key, |_| true).unwrap()].clone())
        .collect()
}

fn keys(count: u64) -> Vec<u64> {
    (0..count).map(|i| hash64(format!("client-{i}"))).collect()
}

#[test]
fn ring_is_deterministic_and_stable() {
    let backends = authorities(3);
    let ring = build_ring(&backends, &[1, 1, 1]);
    assert_eq!(ring.len(), 3 * RING_REPLICAS);

    let key = hash64("client-1.2.3.4");
    let a = ring_pick(&ring, key, |_| true).unwrap();
    let b = ring_pick(&ring, key, |_| true).unwrap();
    assert_eq!(a, b, "same key → same backend");
}

#[test]
fn ring_scales_vnodes_by_weight() {
    let backends = authorities(2);
    let ring = build_ring(&backends, &[1, 3]);
    assert_eq!(ring.len(), RING_REPLICAS + 3 * RING_REPLICAS);
    let b1 = ring.iter().filter(|(_, i)| *i == 1).count();
    assert_eq!(b1, 3 * RING_REPLICAS);
}

#[test]
fn ring_places_a_backend_of_weight_zero_on_no_point() {
    let ring = build_ring(&authorities(2), &[0, 1]);

    assert!(ring.iter().all(|&(_, i)| i == 1));
}

#[test]
fn ring_skips_unhealthy() {
    let backends = authorities(2);
    let ring = build_ring(&backends, &[1, 1]);
    let key = hash64("xyz");
    let pick = ring_pick(&ring, key, |i| i == 1).unwrap();
    assert_eq!(pick, 1);
}

#[test]
fn ring_falls_to_the_next_healthy_backend_clockwise_when_the_owner_is_unhealthy() {
    let ring = build_ring(&authorities(5), &[1; 5]);
    let key = hash64("client-x");
    let owner = ring_pick(&ring, key, |_| true).unwrap();

    let fallback = ring_pick(&ring, key, |i| i != owner).unwrap();

    let start = ring.partition_point(|(p, _)| *p < key);
    let expected = (0..ring.len())
        .map(|off| ring[(start + off) % ring.len()].1)
        .find(|&i| i != owner)
        .unwrap();
    assert_eq!(fallback, expected);
}

#[test]
fn ring_wraps_around_past_its_last_point() {
    let ring = build_ring(&authorities(3), &[1; 3]);

    let pick = ring_pick(&ring, u64::MAX, |_| true).unwrap();

    // No point is above u64::MAX but the hash itself: the walk wraps to the
    // first point of the ring.
    let last = ring.last().unwrap();
    let expected = if last.0 == u64::MAX {
        last.1
    } else {
        ring[0].1
    };
    assert_eq!(pick, expected);
}

#[test]
fn ring_pick_on_an_empty_ring_is_none() {
    assert_eq!(ring_pick(&[], 42, |_| true), None);
}

#[test]
fn ring_pick_with_no_healthy_backend_is_none() {
    let ring = build_ring(&authorities(3), &[1; 3]);

    assert_eq!(ring_pick(&ring, 42, |_| false), None);
}

#[test]
fn removing_a_backend_moves_only_the_keys_it_owned() {
    let before = authorities(10);
    let removed = before[3].clone();
    let after: Vec<String> = before.iter().filter(|a| **a != removed).cloned().collect();
    let keys = keys(10_000);

    let owners_before = owners(&before, &keys);
    let owners_after = owners(&after, &keys);

    let mut moved = 0;
    for (b, a) in owners_before.iter().zip(&owners_after) {
        if *b != removed {
            assert_eq!(a, b, "a key not owned by the removed backend moved");
        } else {
            moved += 1;
        }
    }
    // The removed backend owned about a tenth of the keys; nothing else moved.
    assert!((500..1_500).contains(&moved), "{moved} keys moved");
}

#[test]
fn adding_a_backend_moves_keys_only_onto_it() {
    let before = authorities(10);
    let after = authorities(11);
    let added = after[10].clone();
    let keys = keys(10_000);

    let owners_before = owners(&before, &keys);
    let owners_after = owners(&after, &keys);

    let mut moved = 0;
    for (b, a) in owners_before.iter().zip(&owners_after) {
        if a != b {
            assert_eq!(*a, added, "a key moved to a backend that was already there");
            moved += 1;
        }
    }
    // The new backend takes about an eleventh of the keys.
    assert!((450..1_400).contains(&moved), "{moved} keys moved");
}

#[test]
fn weighted_pick_respects_boundaries() {
    // candidates: idx0 weight 1, idx1 weight 3 → total 4.
    let c = [(0usize, 1u32), (1usize, 3u32)];
    assert_eq!(weighted_pick(&c, 0), 0);
    assert_eq!(weighted_pick(&c, 1), 1);
    assert_eq!(weighted_pick(&c, 3), 1);
}

#[test]
fn weighted_pick_over_every_draw_matches_the_weights() {
    let c = [(0usize, 1u32), (1usize, 3u32), (2usize, 2u32)];
    let mut counts = [0; 3];

    for r in 0..6 {
        counts[weighted_pick(&c, r)] += 1;
    }

    assert_eq!(counts, [1, 3, 2]);
}

#[test]
fn hash64_is_deterministic() {
    assert_eq!(hash64("1.2.3.4"), hash64("1.2.3.4"));
    assert_ne!(hash64("1.2.3.4"), hash64("1.2.3.5"));
}
