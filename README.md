# GFE — General Front End

A high-performance L7 TLS-terminating HTTP reverse proxy written in Rust,
inspired by Google's Front End (GFE) service. GFE is the layer-7 tier designed
to sit directly behind the [`lb`](https://github.com/thewillyhuman/lb)
Maglev L4 load balancer — the component its specification (Section 11) calls
*"Frontend (GFE) Integration"* but deliberately leaves unspecified.

GFE terminates TLS for every service behind a shared set of VIPs, routes HTTP
by host and path to upstream pools, pools long-lived upstream connections,
health-checks backends at L7, and is configured entirely from a hot-reloadable
local file. It is **stateless**: any node is interchangeable, so the L4 LB can
spread connections across a fleet with no coordination.

## Features

- **Centralized TLS termination** — SNI-based certificate selection from a
  hot-swappable cert store; uniform fleet TLS policy (min version, ALPN, HSTS);
  session resumption tickets. Teams never manage certificates.
- **L7 routing** — match by SNI/`Host` (exact + single-label wildcard) and path
  (longest-prefix / exact); forward / redirect / fixed-response actions.
- **Upstream load balancing** — `round_robin`, `least_request` (fewest in-flight),
  and `ring_hash` (consistent-hash session affinity), over the healthy set only.
- **Connection pooling** — long-lived pooled h1/h2 upstream connections via
  `hyper-util`, keyed per backend; TLS to upstreams validated against webpki
  roots (+ optional extra CA), with optional **mTLS** client certificates.
- **L7 health checking** — TCP / HTTP / HTTPS probes with thresholds and a
  per-backend state machine; deduplicated across pools; drives selection live.
- **Lame-duck draining** — a backend signalling a configured drain status moves
  to `DRAINING` (no new requests, in-flight complete) for zero-downtime deploys.
- **Stateless + file config** — bootstrap TOML + hot-reloadable dynamic JSON
  (listeners/routes/pools/certs), watched via inotify, validated wholesale, and
  swapped atomically with `ArcSwap` — in-flight requests never drop
  ([ADR-001](.docs/adr-001-configuration-model.md) model, inherited from `lb`).
- **Last-known-good cache** — a restarted node serves immediately even if the
  config source is briefly unavailable.
- **Conservative retries** — only bodyless idempotent requests, only on
  pre-response failures, against a freshly selected backend; never after any
  response byte is forwarded.
- **Graceful drain** — `SIGTERM` fails `/readyz` (so the L4 LB withdraws the
  node), stops accepting, and drains in-flight requests up to a deadline.
- **ACME http-01** — serves `/.well-known/acme-challenge/*` from a challenge
  store (the CA-ordering driver is a documented integration point).
- **Observability** — Prometheus metrics, structured JSON access + event logs,
  `/healthz` `/readyz` `/metrics`, and an offline routing tracer (`gfe-trace`).

## How it fits with `lb`

```
            clients ── BGP/ECMP ──> [ lb: Maglev L4 nodes ] ──GRE──> [ GFE nodes ]
                                                                          │  TLS terminate, route,
                                                                          │  pool, L7 health-check
                                                                          ▼
                                                                  application backends
        Responses: GFE → client directly (DSR; the L4 LB is never on the return path).
```

GFE registers as a backend pool in `lb`. Each GFE node runs a GRE tunnel and
holds the service VIP on its loopback (see `deploy/backend-onboard.sh`), so
GRE-decapsulated packets reach GFE's socket and responses return via DSR.

## Performance

All numbers from `cargo bench` (criterion, release profile, single-threaded, Apple M-series). Reproduce with `cargo bench -p gfe-router --bench routing`, `-p gfe-upstream --bench selection`, `-p gfe-tls --bench handshake`.

**Routing (`gfe-router`)** — match cost is **O(1) in the number of routes** (exact-host hashmap + bounded per-host prefix list):

```
route_match_hit/10        71.7 ns
route_match_hit/100       72.8 ns
route_match_hit/1000      74.8 ns      ← flat from 10 → 1000 routes
route_match_miss/1000     59.2 ns
route_table_compile/10     4.22 µs
route_table_compile/100   40.5 µs
route_table_compile/1000   444 µs      (control plane, on reload only)
```

**Load-balancer selection (`gfe-upstream`, 20 backends)**:

```
select_round_robin/20          849 ns
select_weighted_round_robin/20 932 ns
select_least_request/20       1.07 µs
select_ring_hash/20           1.21 µs
ring_build/20                  216 µs   (control plane, on reload only)
hash64                        22.9 ns
```

**TLS (`gfe-tls`)**:

```
tls13_full_handshake_ecdsa_p256   133 µs   (full client+server handshake, in-process)
sni_cert_resolve                 52.4 ns   (per-ClientHello certificate lookup)
```

### Throughput analysis

The dominant cost at the GFE tier is **TLS handshakes**, not request processing or bandwidth:

| Operation | Cost | Relative |
|---|---|---|
| SNI cert resolve | 52 ns | 1× |
| Route match | 72 ns | 1.4× |
| LB selection | ~0.9 µs | ~17× |
| **Full TLS 1.3 handshake (ECDSA P-256)** | **133 µs** | **~2500×** |

- **Established connections are request-bound, not GFE-bound.** On a warm keep-alive / HTTP-2 connection, GFE's own per-request work is route match (72 ns) + LB selection (~0.9 µs) ≈ **~1 µs**; the rest is hyper's HTTP parse/serialize. So steady-state request throughput is effectively hyper-limited — comfortably **>100k req/s/core** on warm connections.
- **New HTTPS connections are handshake-bound.** A full TLS 1.3 handshake measures ~133 µs here (both sides, in one thread); the server's share — the ECDSA signature + ECDHE — is what consumes a serving core. That puts a single core in the order of **10–15k new ECDSA-P256 handshakes/s**, scaling ~linearly with cores. This is exactly why **session resumption tickets** and **ECDSA (not RSA-2048) certificates** are the levers that matter — an RSA-2048 server signature is several× more expensive per handshake.
- **Capacity planning is handshakes/sec and concurrent connections, not Gbps.** Bandwidth is bounded by the kernel/NIC and body streaming is zero-copy through hyper; the CPU budget goes to handshakes.

**Key findings:**

- **O(1) routing**: match time is flat (72 ns) from 10 to 1000 routes — the exact-host map means added routes don't slow matching.
- **Selection is ~150× cheaper than a handshake**, so the LB policy choice is never the bottleneck. (The per-call health lookup does allocate per backend; it could be made allocation-free if selection ever dominated, but at ~0.9 µs vs a 133 µs handshake it is far from the critical path.)
- **All O(n) work is on the control plane** (`route_table_compile`, `ring_build`) — it runs on config reload via a shadow copy + atomic swap, never on the request path.
- **`ring_hash` adds ~0.3 µs over round-robin** for full session-affinity — cheap enough to use wherever stickiness is wanted.

### End-to-end load test

A self-contained harness (`crates/gfe-loadtest` + `scripts/loadtest.sh`) drives the **real `gfe-node` binary** over loopback in front of a mock upstream, layer by layer. Reproduce with `./scripts/loadtest.sh 64 6` (64 connections, 6 s/scenario):

```
scenario                          mode        result
http  · fixed (GFE overhead)      keepalive   159421 req/s   p50 392µs  p99 701µs   errors=0
http  · proxy (+upstream)         keepalive    71662 req/s   p50 877µs  p99 1.29ms  errors=0
https · proxy (warm TLS)          keepalive    70960 req/s   p50 883µs  p99 1.33ms  errors=0
https · proxy (new TLS/req, c=8)  reconnect    12231 req/s   p50 632µs  p99 874µs   errors=0
```

What each row shows (Apple M-series, all processes sharing the host's cores — these are **conservative, comparative** loopback numbers, not a tuned NIC benchmark):

- **GFE request overhead is tiny.** Pure proxy work (route + select + relay) sustains **~159k req/s** on warm connections; the proxy itself is not the bottleneck.
- **The upstream hop, not TLS, is the main steady-state cost.** Adding the backend leg roughly halves throughput (159k → 72k); enabling TLS on the warm connection costs **~1%** more (72k → 71k) — because the handshake is amortized once and never repeated.
- **New-TLS-per-request lands at ~12k handshakes/s** even at just 8 connections — which **matches the 133 µs micro-benchmark prediction** (≈10–15k/core). This is the number that scales with cores and is the real capacity lever, reinforcing why session resumption matters.
- **Loopback caveat:** the `reconnect` row uses low concurrency on purpose — hammering brand-new connections at high concurrency exhausts loopback ephemeral ports (TIME_WAIT), an artifact of the test host, not GFE.

### What can a single instance handle?

Reading the numbers above as operator capacity. **These are lower bounds**: in this test the load client *and* the mock upstream ran on the same laptop, competing with `gfe-node` for the same cores — a dedicated instance on server hardware does strictly better.

| Dimension | One instance (measured, this test host) | What bounds it |
|---|---|---|
| **HTTPS req/s, warm connections** (real path: TLS terminate → route → pooled upstream) | **~71,000 req/s** | upstream hop + HTTP processing (CPU) |
| **Plain proxy req/s** (no TLS) | ~72,000 req/s | upstream hop (TLS adds only ~1% when warm) |
| **GFE-only req/s** (fixed response, no upstream) | ~159,000 req/s | hyper HTTP parse/serialize (headroom above) |
| **New HTTPS connections/s** (full TLS handshake each) | **~12,000 handshakes/s** | ECDSA-P256 sign + ECDHE (CPU), scales ~linearly with cores |
| **Concurrent connections held** | ~100,000 (default `max_connections`) | FD limit (`LimitNOFILE`, 1M in the unit) + memory |
| **Request latency @ 64 in-flight** | p50 ≈ 0.88 ms, p99 ≈ 1.33 ms | — |

Put differently, **a single GFE instance sustained ~71k fully-terminated HTTPS requests per second** to a live backend on a laptop — on the order of **6 billion requests/day** at that rate — while *also* hosting the load generator and backend. Two practical rules of thumb fall out of this:

- **If clients reuse connections** (HTTP-keepalive / HTTP-2, the normal case), an instance is **request-bound** and serves tens of thousands of req/s per core — you'll saturate the upstream or the NIC before GFE.
- **If clients open a fresh TLS connection per request** (no keepalive, no resumption), an instance is **handshake-bound** at ~12k/s/core. This is the regime to size for, and the reason **session-resumption tickets** and **ECDSA (not RSA-2048) certificates** matter — RSA-2048 server signatures are several× costlier per handshake.

**Scaling is horizontal and linear.** GFE nodes are stateless and sit behind the `lb` L4 Maglev layer, which spreads connections across them with no coordination — so *N* instances deliver ≈ *N×* this capacity. Size the fleet with N+1 headroom (any N−1 nodes must carry peak), driven by your **handshake rate** and **peak concurrent connections**, not bandwidth.

## Quick start

```bash
# Build
cargo build --release

# Validate config
./target/release/gfe-node --config config/gfe.example.toml --check-config

# Generate a dynamic config scaffold
./deploy/generate-config.sh --host app.example.org --backend 10.0.0.1:8443 -o /tmp/gfe-dynamic.json

# Run (binds the listeners in the dynamic config; serves /metrics on metrics_addr)
./target/release/gfe-node --config config/gfe.example.toml

# Trace how a request would route, offline
./target/release/gfe-trace --config config/gfe.example.toml --host atlas.example.org --path /
```

## Project structure

```
crates/
  gfe-types/        Domain types + config (bootstrap TOML + dynamic JSON)
  gfe-router/       Compiled route table: host (exact/wildcard) + path matching
  gfe-tls/          Cert store, SNI resolver, TLS policy, ACME challenge store
  gfe-upstream/     Pools, LB policies, shared health map, pooled hyper client
  gfe-proxy/        Data plane: acceptor, TLS termination, routing, forwarding
  gfe-health/       L7 probes (TCP/HTTP/HTTPS), state machine, checker
  gfe-config/       Load, validate, apply (atomic swap), watch, cache
  gfe-controller/   Orchestrator: config + health + cache + hot-reload
  gfe-metrics/      Prometheus counters/gauges/histograms
  gfe-node/         Main binary: proxy + controller + ops server
  gfe-trace/        Offline routing-decision tracer CLI
config/
  gfe.example.toml            Bootstrap node config
  gfe-dynamic.example.json    Dynamic config (listeners/routes/pools/certs)
deploy/
  gfe-node.service            systemd unit (hardened, CAP_NET_BIND_SERVICE only)
  backend-onboard.sh          GRE tunnel + loopback VIP (DSR) for L4 integration
  generate-config.sh          Scaffold a dynamic config
  validate-config.sh          --check-config wrapper
  grafana/gfe-dashboard.json  Prebuilt dashboard
```

## Development

```bash
cargo test --workspace          # unit + integration tests
cargo clippy --workspace --all-targets
cargo bench -p gfe-router --bench routing
cargo bench -p gfe-upstream --bench selection
cargo bench -p gfe-tls --bench handshake
./scripts/loadtest.sh 64 6      # end-to-end load test (mock upstream + real node)
```

## Documentation

- **[Design specification](.docs/spec.md)** — full architecture and protocol details.

## License

MIT
