use criterion::{black_box, criterion_group, criterion_main, Criterion};
use gfe_types::{LbPolicy, PoolId, Scheme, Upstream, UpstreamPool};
use gfe_upstream::policy::{build_ring, hash64};
use gfe_upstream::{HealthMap, PoolSet};

fn pool(policy: LbPolicy, n: usize, weighted: bool) -> UpstreamPool {
    let upstreams = (0..n)
        .map(|i| Upstream {
            host: format!("10.0.0.{i}"),
            port: 8443,
            weight: if weighted { (i as u32 % 5) + 1 } else { 1 },
        })
        .collect();
    UpstreamPool {
        id: PoolId("p".into()),
        scheme: Scheme::Http,
        lb_policy: policy,
        upstreams,
        health_check: None,
    }
}

fn bench(c: &mut Criterion) {
    let health = HealthMap::new(true);
    let n = 20;

    let rr = PoolSet::build(&[pool(LbPolicy::RoundRobin, n, false)]);
    let rr_pool = rr.get(&PoolId("p".into())).unwrap().clone();
    c.bench_function("select_round_robin/20", |b| {
        b.iter(|| black_box(rr_pool.select(black_box(&health), None)))
    });

    let wrr = PoolSet::build(&[pool(LbPolicy::RoundRobin, n, true)]);
    let wrr_pool = wrr.get(&PoolId("p".into())).unwrap().clone();
    c.bench_function("select_weighted_round_robin/20", |b| {
        b.iter(|| black_box(wrr_pool.select(black_box(&health), None)))
    });

    let lr = PoolSet::build(&[pool(LbPolicy::LeastRequest, n, true)]);
    let lr_pool = lr.get(&PoolId("p".into())).unwrap().clone();
    c.bench_function("select_least_request/20", |b| {
        b.iter(|| black_box(lr_pool.select(black_box(&health), None)))
    });

    let rh = PoolSet::build(&[pool(LbPolicy::RingHash, n, true)]);
    let rh_pool = rh.get(&PoolId("p".into())).unwrap().clone();
    let mut k: u64 = 0;
    c.bench_function("select_ring_hash/20", |b| {
        b.iter(|| {
            k = k.wrapping_add(0x9E37_79B9_7F4A_7C15);
            black_box(rh_pool.select(black_box(&health), Some(k)))
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
