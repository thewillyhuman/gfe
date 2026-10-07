//! Cost of selecting a backend, per policy, over a pool of 20, and of
//! building a ring on reload.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use netkit_health_checking::HealthMap;
use netkit_load_balancing::policy::{build_ring, hash64};
use netkit_load_balancing::{Backend, Policy, PoolSet, PoolSpec};

fn pool(policy: Policy, n: usize, weighted: bool) -> PoolSpec<()> {
    let backends = (0..n)
        .map(|i| Backend {
            host: format!("10.0.0.{i}"),
            port: 8443,
            weight: if weighted { (i as u32 % 5) + 1 } else { 1 },
        })
        .collect();
    PoolSpec {
        id: "p".into(),
        policy,
        backends,
        max_in_flight: None,
        payload: (),
    }
}

fn bench(c: &mut Criterion) {
    let health = HealthMap::new(true);
    let n = 20;

    let rr = PoolSet::build(&[pool(Policy::RoundRobin, n, false)], &health).unwrap();
    let rr_pool = rr.get("p").unwrap().clone();
    c.bench_function("select_round_robin/20", |b| {
        b.iter(|| black_box(rr_pool.select(None)))
    });

    let wrr = PoolSet::build(&[pool(Policy::RoundRobin, n, true)], &health).unwrap();
    let wrr_pool = wrr.get("p").unwrap().clone();
    c.bench_function("select_weighted_round_robin/20", |b| {
        b.iter(|| black_box(wrr_pool.select(None)))
    });

    let lr = PoolSet::build(&[pool(Policy::LeastRequest, n, true)], &health).unwrap();
    let lr_pool = lr.get("p").unwrap().clone();
    c.bench_function("select_least_request/20", |b| {
        b.iter(|| black_box(lr_pool.select(None)))
    });

    let rh = PoolSet::build(&[pool(Policy::RingHash, n, true)], &health).unwrap();
    let rh_pool = rh.get("p").unwrap().clone();
    let mut k: u64 = 0;
    c.bench_function("select_ring_hash/20", |b| {
        b.iter(|| {
            k = k.wrapping_add(0x9E37_79B9_7F4A_7C15);
            black_box(rh_pool.select(Some(k)))
        })
    });

    // Ring construction cost (control-plane, on reload).
    let authorities: Vec<String> = (0..n).map(|i| format!("10.0.0.{i}:8443")).collect();
    let weights: Vec<u32> = (0..n).map(|i| (i as u32 % 5) + 1).collect();
    c.bench_function("ring_build/20", |b| {
        b.iter(|| black_box(build_ring(black_box(&authorities), black_box(&weights))))
    });

    c.bench_function("hash64", |b| {
        b.iter(|| black_box(hash64(black_box("1.2.3.4"))))
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
