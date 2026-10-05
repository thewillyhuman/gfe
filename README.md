# GFE — General Front End

A high-performance L7 TLS-terminating HTTP reverse proxy, written in Rust on
top of [Cloudflare Pingora](https://github.com/cloudflare/pingora) and built
to be observed and operated.

GFE terminates TLS for every service behind a shared set of addresses, routes
HTTP by host and path to upstream pools, pools long-lived upstream
connections, health-checks backends at L7, and is configured entirely from a
hot-reloadable local file. It is **stateless**: any node is interchangeable,
so whatever spreads traffic over a fleet of them (an L4 load balancer, DNS,
anycast) needs no coordination with it, and nothing in GFE assumes how
traffic reaches a node.

## Features

- **Centralized TLS termination** — SNI-based certificate selection from a
  hot-swappable cert store; uniform fleet TLS policy (min version, ALPN, HSTS);
  session resumption tickets. Teams never manage certificates. A certificate
  rotated in place on disk is picked up within 10 s, no restart needed.
- **L7 routing** — match by SNI/`Host` (exact + single-label wildcard) and path
  (longest-prefix / exact); forward / redirect / fixed-response actions.
- **gRPC** — unary and streaming calls are proxied end to end over HTTP/2,
  message by message, with trailers; backends are reached over TLS (`https`,
  HTTP/2 by ALPN) or cleartext HTTP/2 (`h2c`) and health-checked with the gRPC
  health protocol. Calls are bounded by their client's deadline rather than by
  proxy timeouts, and a call GFE cannot serve fails with a proper `grpc-status`.
- **Upstream load balancing** — `round_robin`, `least_request` (fewest in-flight),
  and `ring_hash` (consistent-hash session affinity), over the healthy set only.
- **Connection pooling** — long-lived pooled HTTP/1.1 and HTTP/2 upstream
  connections; TLS to upstreams validated against the system's trust store
  (+ optional extra CA), with optional **mTLS** client certificates.
- **L7 health checking** — TCP / HTTP / HTTPS / gRPC (`grpc.health.v1`) probes
  with thresholds and a per-backend state machine; deduplicated across pools;
  drives selection live.
- **Lame-duck draining** — a backend signalling a configured drain status moves
  to `DRAINING` (no new requests, in-flight complete) for zero-downtime deploys.
- **Stateless + file config** — bootstrap TOML + hot-reloadable dynamic JSON
  (listeners/routes/pools/certs), watched via inotify, validated wholesale, and
  swapped atomically with `ArcSwap` — in-flight requests never drop, and
  listeners are bound and released on reload without a restart.
- **Last-known-good cache** — a restarted node serves immediately even if the
  config source is briefly unavailable.
- **Conservative retries** — only bodyless idempotent requests, only on
  pre-response failures, against a freshly selected backend; never after any
  response byte is forwarded.
- **Graceful drain** — `SIGTERM` fails `/readyz` (so whatever sends the node
  traffic withdraws it), stops accepting, and asks clients to leave without
  losing a request (`GOAWAY` on HTTP/2, `Connection: close` on HTTP/1), up to
  a deadline. The node exits as soon as the last client has left.
- **Upgrades in place** — `systemctl reload gfe-node` (`SIGUSR2`) replaces
  the running node with the binary now on disk without closing a listening
  socket: no connection is refused, and the old process drains while its
  successor serves. A successor that does not start changes nothing.
  `SIGHUP` and `SIGUSR1` are logged and ignored, never fatal.
- **Observability** — Prometheus metrics for requests, latency, status and gRPC
  codes, body and wire bytes, broken-off exchanges, connection close reasons,
  TLS parameters and handshake failures, upstream failures by kind, and node
  saturation; one structured JSON event per request and per connection, logged
  when it is over, to a file or standard output, by a writer that never holds
  up a request and counts what it had to drop; `/healthz` `/readyz`
  `/metrics`; alert rules and a dashboard. See the
  [observability guide](docs/observability.md).
- **Kernel view (eBPF)** — accept-queue wait, round-trip time,
  retransmissions and how connections end, per listener and per backend,
  from a small eBPF program attached to the node's own cgroup. It watches
  sockets, not packets, so it does not care how traffic reaches the node.
  Part of every node: the systemd unit grants what it needs (`CAP_BPF`,
  `CAP_NET_ADMIN`), and a node that cannot attach it says so (its log,
  `gfe_ebpf_attached`, an alert) and serves without it.

## Built on Pingora

Pingora is the HTTP engine: HTTP/1.1 and HTTP/2 on both legs, the proxy state
machine, and the pooled, TLS-capable connections to backends. GFE is what a
node adds around it.

```
 clients ──► listening sockets ──► TLS termination ──► Pingora HTTP proxy ──► backends
             (gfe-core: listener)   (gfe-tls, rustls)   │  calls into gfe-core: proxy
                                                        │    host rules, routing      (gfe-core: routing)
                                                        │    backend selection        (gfe-load-balancing)
                                                        │    over the healthy set     (gfe-health-checking)
                                                        │    retries, timeouts, the answers GFE writes itself
                                                        └──► metrics and one event per request (gfe-observability)
```

The edge (listening sockets, accept loops, TLS termination, what is counted
and logged about every connection, draining) and the process lifecycle
(signals, upgrade in place) are GFE's own rather than Pingora's listening
service and server, because of what a node promises its operators: listeners
that come and go with a reload, a count and a reason for every handshake that
fails and every connection that closes, a drain that ends when the last
client has left, and an upgrade that changes nothing when the successor does
not start.

## Performance

All numbers below were measured on one laptop (Apple M-series), where the
load client and the mock backend compete with the node for the same cores:
read them as relative costs and lower bounds, not as a tuned benchmark.

### Micro-benchmarks

`cargo bench` (criterion, release profile, single thread):

**Routing (`gfe-core`)** — matching is **O(1) in the number of routes** (an
exact-host map and a bounded list of prefixes per host):

```
route_match_hit/10        48.7 ns
route_match_hit/100       47.7 ns
route_match_hit/1000      47.5 ns      ← flat from 10 to 1000 routes
route_match_miss/1000     35.3 ns
route_table_compile/10    3.57 µs
route_table_compile/100   36.5 µs
route_table_compile/1000   418 µs      (on reload only)
```

**Backend selection (`gfe-load-balancing`, 20 backends)**:

```
select_round_robin/20           800 ns
select_weighted_round_robin/20  861 ns
select_least_request/20        1.09 µs
select_ring_hash/20            1.12 µs
ring_build/20                   211 µs   (on reload only)
hash64                         23.6 ns
```

**TLS (`gfe-tls`)**:

```
tls13_full_handshake_ecdsa_p256   134 µs   (client and server sides, in one thread)
sni_cert_resolve                 38.1 ns   (certificate lookup per ClientHello)
```

What they say: routing (48 ns) and selection (about 1 µs) are noise next to a
full TLS handshake (134 µs for both sides; the server's share, an ECDSA
signature and a key exchange, is what costs a serving core). Everything that
grows with the size of the config (`route_table_compile`, `ring_build`) runs
on reload, on a copy that is then swapped in, never on the path of a request.

### End-to-end load test

`hack/loadtest.sh` runs the **real `gfe-node` binary** on loopback in front of
a mock backend (`gfe-loadtest`), one scenario after the other. `./hack/loadtest.sh 64 6`
(64 connections, 6 s per scenario):

```
scenario                          mode        result
http  · fixed (GFE overhead)      keepalive   120856 req/s   p50 506µs  p99 1.06ms  errors=0
http  · proxy (+upstream)         keepalive    64509 req/s   p50 958µs  p99 1.95ms  errors=0
https · proxy (warm TLS)          keepalive    63891 req/s   p50 966µs  p99 1.99ms  errors=0
https · proxy (new TLS/req, c=8)  reconnect    11918 req/s   p50 649µs  p99 901µs   errors=0
```

- **The node's own work is small.** Answering a request itself (routing and
  a fixed response, no backend) runs at about 120k req/s on kept
  connections.
- **The hop to the backend is the main cost of a proxied request**, not TLS:
  adding the backend roughly halves the throughput (121k → 65k), and TLS on
  a connection that is already established costs about 1% more (65k → 64k).
- **A new TLS connection per request runs at about 12k req/s with 8 client
  workers.** The load client resumes its TLS sessions, so this row is the
  price of a connection (TCP, a resumed handshake, one request), not of a
  full handshake: a client that cannot resume pays the 134 µs above, most of
  it on the node.

### Sizing a node

- **Clients that reuse connections** (keep-alive, HTTP/2: the normal case)
  make a node request-bound, at tens of thousands of requests per second per
  node on this laptop: the backends or the network saturate first.
- **Clients that open a connection per request** make it handshake-bound.
  This is the regime to size for, and why **session resumption** and
  **ECDSA rather than RSA certificates** matter: an RSA-2048 signature costs
  several times an ECDSA P-256 one, an RSA-4096 one far more.
- **Large uploads and many idle connections** are bound by bytes and by
  memory, not by request rate: bodies are streamed, never buffered whole, and
  an idle TLS connection costs memory and a file descriptor (the unit sets
  `LimitNOFILE=1048576`; `max_connections` defaults to 100,000).

Nodes are stateless, so capacity grows with their number: size a fleet so
that it carries its peak with one node missing, by its **handshake rate**,
its **concurrent connections** and its **bytes**, rather than by requests
per second alone.

## Quick start

Building needs Rust (1.88 or later), a C compiler and `cmake` (Pingora builds
zlib-ng) and, on Linux, `clang` (the eBPF program of the kernel view).

```bash
cargo build --release

# Validate config (with the dynamic config it names, /etc/gfe/gfe-dynamic.json)
./target/release/gfe-node --config docs/examples/gfe.example.toml --check-config

# Validate a candidate dynamic config before it replaces the deployed one
./target/release/gfe-node --config docs/examples/gfe.example.toml --check-config \
    --dynamic-config /tmp/gfe-dynamic.candidate.json

# Run (binds the listeners in the dynamic config; serves /metrics on metrics_addr)
./target/release/gfe-node --config docs/examples/gfe.example.toml
```

## See it running

[`hack/demo/`](hack/demo/) is a local playground: one node, HTTP and gRPC
backends, clients that misbehave, and Prometheus, Loki and Grafana with the
dashboards loaded. The [demo guide](docs/demo.md) says what runs in it and
what to try.

```bash
cd hack/demo && docker compose up -d --build   # then open http://localhost:13000
```

## Project structure

A Cargo workspace with one crate per capability, each named after what it
does, at the root of the repository.

```
gfe-core/             The reverse proxy, on Pingora: serving the connections of
                      clients (listeners, TLS termination, limits, drain),
                      what happens to a request (routing, forwarding, retries,
                      errors, accounting), and keeping in step with the config
gfe-tls/              TLS termination: certificates by SNI, the TLS policy,
                      the handshake and what it negotiated
gfe-load-balancing/   Which backend gets a request: pools, selection policies
gfe-health-checking/  Which backends are alive: probes, state machine, checker
gfe-config/           The two config files: their schema, loading, validation
gfe-observability/    What a node tells about itself: Prometheus metrics, the
                      log that never blocks
gfe-limits/           Counting and capping what a node holds at once
gfe-ebpf/             The kernel view: the eBPF program (bpf/) and its loader
gfe-node/             The binary: CLI, wiring, signals, the ops endpoints,
                      upgrade in place
gfe-loadtest/         Load generator for benchmarks (not shipped)

distribution/         What ships besides the binary
  systemd/            The unit of gfe-node
  docker/             The image of gfe-node
  grafana/            Prebuilt dashboard
  prometheus/         Alerting rules (GFE + host network)
docs/                 Specification, guides, and the example configs
hack/
  create-tag.sh       Tag a release, listing the commits since the last one
  loadtest.sh         End-to-end load test of the real binary
  demo/               Local playground: node, backends, traffic, monitoring
  rpm/                What the RPM runs when installed and removed
```

Dependencies go one way: `gfe-node` → `gfe-core` → the capability crates →
`gfe-config`, `gfe-observability`, `gfe-limits`. No crate contains `unsafe`.

## Development

```bash
cargo test --workspace          # unit + functional tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo deny check                # advisories, licenses, sources
```

Tests are the only thing that stands between a change and a regression, and
there are three kinds:

- **Unit tests** sit next to the code: `foo.rs` has its tests in
  `foo_test.rs`.
- **Functional tests** are in each crate's `tests/` directory, one file per
  feature. Those of `gfe-core` run a whole proxy in-process, with real TLS
  termination, in front of mock backends.
- **Tests of the binary** are in `gfe-node/tests/`: they start `gfe-node` as
  an operator would and cover what only the process can show (its flags, its
  log, the ops endpoints, signals, draining, upgrading in place), and a
  smoke test walks through the product end to end.

Every feature listed above has at least one functional test, or test of the
binary, that fails when the feature breaks.

The kernel view needs Linux and privileges. Its tests skip themselves where
they cannot run and say so; CI runs them as root. On a development machine
that is not Linux, run the suite in a container as well:

```bash
docker run --rm -v "$PWD":/gfe:ro -w /gfe -e CARGO_TARGET_DIR=/tmp/target \
    --cap-add BPF --cap-add NET_ADMIN rust:1 bash -c \
    'apt-get update -qq && apt-get install -y -qq cmake clang >/dev/null && cargo test --workspace'
```

CI runs the tests with [cargo-nextest](https://nexte.st), which reports the
whole workspace as one result instead of one per test binary:

```bash
cargo nextest run --workspace --no-fail-fast --failure-output immediate-final
cargo test --workspace --doc    # doctests, which nextest does not run
```

Benchmarks and the load test:

```bash
cargo bench -p gfe-core --bench routing
cargo bench -p gfe-load-balancing --bench selection
cargo bench -p gfe-tls --bench handshake
./hack/loadtest.sh 64 6         # end-to-end load test (mock upstream + real node)
```

## Documentation

- **[Specification](docs/spec.md)** — architecture and behaviour, in detail.
- **[Observability guide](docs/observability.md)** — which signal answers which question.
- **[Demo guide](docs/demo.md)** — the local playground and what to try in it.
- **[RPM guide](docs/rpm.md)** — building the package and managing a node with Puppet.

## License

MIT
