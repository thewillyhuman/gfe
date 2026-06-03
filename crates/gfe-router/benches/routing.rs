use criterion::{black_box, criterion_group, criterion_main, Criterion};
use gfe_router::RouteTable;
use gfe_types::{DynamicConfig, ListenProtocol, Listener, ListenerId, Route, RouteAction, RouteId};

fn config_with(n: usize) -> DynamicConfig {
    let listener = Listener {
        id: ListenerId("https".into()),
        address: "0.0.0.0".parse().unwrap(),
        port: 443,
        protocol: ListenProtocol::Https,
    };
    let mut routes = Vec::with_capacity(n * 2);
    for i in 0..n {
        // An exact-host root route and an /api/ prefix route per host.
        routes.push(Route {
            id: RouteId(format!("r{i}-root")),
            listener: ListenerId("https".into()),
            host: format!("host{i}.example.org"),
            path_prefix: "/".into(),
            action: RouteAction::Forward(format!("pool{i}")),
        });
        routes.push(Route {
            id: RouteId(format!("r{i}-api")),
            listener: ListenerId("https".into()),
            host: format!("host{i}.example.org"),
            path_prefix: "/api/".into(),
            action: RouteAction::Forward(format!("pool{i}-api")),
        });
    }
    DynamicConfig {
        listeners: vec![listener],
        routes,
        ..Default::default()
    }
}

fn bench(c: &mut Criterion) {
    let listener = ListenerId("https".into());

    for &n in &[10usize, 100, 1000] {
        let cfg = config_with(n);
        let table = RouteTable::compile(&cfg);
        let host = format!("host{}.example.org", n / 2);

        c.bench_function(&format!("route_match_hit/{n}"), |b| {
            b.iter(|| {
                table.match_request(
                    black_box(&listener),
                    black_box(&host),
                    black_box("/api/users"),
                )
            })
        });
        c.bench_function(&format!("route_match_miss/{n}"), |b| {
            b.iter(|| {
                table.match_request(
                    black_box(&listener),
                    black_box("nope.example.org"),
                    black_box("/"),
                )
            })
        });
        c.bench_function(&format!("route_table_compile/{n}"), |b| {
            b.iter(|| RouteTable::compile(black_box(&cfg)))
        });
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
