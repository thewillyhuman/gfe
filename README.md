# GFE — General Front End

A high-performance L7 TLS-terminating HTTP reverse proxy, written in Rust and
built to be observed and operated.

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
- **Rate limiting** — a cap on the new connections one client address may
  open per second, over all listeners; a connection over it is closed as
  soon as it is accepted and counted, and costs the other clients nothing.
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

## Built on netkit

GFE is built on **netkit**, a set of libraries in this repository for
building networked systems. They know nothing about GFE: each does one job,
and reports what happened through return values and small traits, so that
the product decides what becomes a metric or a log line.

| Library | What it is for |
|---|---|
| `netkit-http` | HTTP/1.1 and HTTP/2 over any byte stream: serving a connection, and a pooled client and single connections towards servers |
| `netkit-tls` | TLS in both directions: termination (certificates by SNI, the policy, what a handshake settled on or why it failed) and origination (the trust store, a client certificate) |
| `netkit-dns` | Host names to addresses, through the system's resolver behind a cache |
| `netkit-load-balancing` | Pools and selection policies: which backend, among the healthy ones, gets a request |
| `netkit-health-checking` | Which backends are alive: probes, a per-backend state machine, the checker that runs them |
| `netkit-rate-limiting` | Caps on how much is in use at once and on how often something happens |
| `netkit-listen` | Listening sockets, accept loops and connection limits, draining, and handing sockets to a successor |
| `netkit-kernel` | The kernel's view of a process's TCP connections, from an eBPF program |
| `netkit-observability` | A Prometheus registry and its exposition, and a log that never blocks |

```
 clients ──► listening sockets ──► TLS termination ──► HTTP/1.1, HTTP/2 ──► gfe-proxy: the request handler
             (netkit-listen)        (netkit-tls)        (netkit-http)         host rules, routing
                                                                              backend selection     (netkit-load-balancing)
                                                                              over the healthy set  (netkit-health-checking)
                                                                              retries, timeouts, the answers GFE writes itself
                                                                              metrics, one event per request and per connection
                                                                                │                   (netkit-observability)
 backends ◄── pooled connections, HTTP/1.1 or HTTP/2, over TLS or not ◄─────────┘
              (netkit-http, netkit-tls, netkit-dns)
```

GFE itself (`gfe/`) is what makes them a front end: the two config files,
the edge (which listener a connection came in on, what is counted and
logged about it), the request handler, keeping in step with the config, and
the binary with its signals, ops endpoints and upgrade in place.

**Dependencies.** The rule is to depend on as little as possible, and never
on a library that decides how the program is built: a dependency is a risk,
and a framework is a risk the whole program takes. Under the libraries, the
only third-party code that speaks a protocol is hyper (with h2) and rustls,
on the tokio runtime. hyper is named by `netkit-http` alone and rustls by
`netkit-tls` alone; everything else reaches them through those libraries, so
replacing either is a change to one crate. The few other crates with one job
each are also named by one library only (`aya` by `netkit-kernel`, `socket2`
by `netkit-listen`, `prometheus-client` and `tracing-subscriber` by
`netkit-observability`). The libraries are meant to outlive this use of
them, as the ground for the next networked system; GFE is the first one
built on them. The `gfe-node` binary is built from 207 crates, 12 of them
this repository's.

## Performance

All numbers below were measured on one laptop (Apple M-series), where the
load client and the mock backend compete with the node for the same cores:
read req/s and latencies as relative costs and lower bounds, not as a tuned
benchmark. What isolates the node is its own CPU per request, which the
load test prints with each row.

### Micro-benchmarks

`cargo bench` (criterion, release profile, single thread):

**Routing (`gfe-proxy`)** — matching is **O(1) in the number of routes** (an
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

**Backend selection (`netkit-load-balancing`, 20 backends)** — a pool reads
the health of each backend from a handle it took when it was built, so
selecting looks nothing up:

```
select_round_robin/20           167 ns
select_weighted_round_robin/20  234 ns
select_least_request/20         462 ns
select_ring_hash/20             640 ns
ring_build/20                   211 µs   (on reload only)
hash64                         23.6 ns
```

**TLS (`netkit-tls`)**:

```
tls13_full_handshake_ecdsa_p256   134 µs   (client and server sides, in one thread)
sni_cert_resolve                 38.1 ns   (certificate lookup per ClientHello)
```

What they say: routing (48 ns) and selection (under a microsecond) are
noise next to a full TLS handshake (134 µs for both sides in memory; the
server's share, an ECDSA signature and a key exchange, is what costs a
serving core). Everything that grows with the size of the config
(`route_table_compile`, `ring_build`) runs on reload, on a copy that is then
swapped in, never on the path of a request.

### End-to-end load test

`hack/loadtest.sh` runs the **real `gfe-node` binary** on loopback in front of
a mock backend (`gfe-loadtest`), one scenario after the other, with the node
set up as in production: its access log written to a file, an ECDSA P-256
certificate on the HTTPS listener. Each row ends with the node's own CPU per
request. `./hack/loadtest.sh 64 6` (64 connections, 6 s per scenario):

```
scenario                              mode                result                                                     node CPU
http  · fixed (GFE overhead)          keepalive           148046 req/s   p50 412µs   p99 879µs   errors=0             33 µs/req
http  · proxy (+upstream)             keepalive            74294 req/s   p50 839µs   p99 1.48ms  errors=0             70 µs/req
http  · upload 400KiB (+upstream)     keepalive            10294 req/s   p50 6.21ms  p99 7.43ms  errors=0  4021 MiB/s  314 µs/req
https · proxy (warm TLS)              keepalive            73895 req/s   p50 839µs   p99 1.53ms  errors=0             70 µs/req
https · proxy + 2000 idle conns       keepalive            74734 req/s   p50 832µs   p99 1.57ms  errors=0             69 µs/req
https · proxy (resumed TLS/req, c=8)  reconnect            11835 req/s   p50 654µs   p99 871µs   errors=0            274 µs/req
https · proxy (full TLS/req, c=8)     reconnect+full-tls   11660 req/s   p50 665µs   p99 884µs   errors=0            289 µs/req
```

- **The node's own work is small.** Answering a request itself (routing and
  a fixed response, no backend) costs the node about 33 µs of CPU, its log
  line included (the access log is 6 to 9 µs of any request), and runs at
  about 145k req/s on kept connections.
- **The hop to the backend is the main cost of a proxied request**, not
  TLS: the backend doubles the CPU per request (33 → 70 µs) and halves the
  throughput, and TLS on a connection that is already established costs
  nothing measurable. Most of a proxied request's CPU goes to the kernel,
  moving bytes on four sockets, and to the HTTP stack on both legs; GFE's
  own code is a few microseconds of it.
- **Bytes are cheaper than requests.** An upload of 400 KiB, the request
  of a telemetry collector behind the node, costs the node some 314 µs of
  CPU, under 1 µs per KiB, and 4 GiB/s go through it on loopback at
  10,000 such requests per second: a node in front of such a collector is
  bound by its network, not by its CPU.
- **Idle connections cost the requests nothing.** With 2,000 kept TLS
  connections that send nothing, the CPU per request of the others is
  the same (69 against 70 µs); what an idle connection costs is memory
  and a file descriptor.
- **A new TLS connection per request costs the node about 280 µs**, of
  which the handshake is a small part: a full TLS 1.3 handshake with a
  P-256 certificate costs some 15 µs more than a resumed one, because
  resumption still runs a key exchange. What a fresh connection costs is
  the connection itself: accept, socket options, the TLS records, the
  request, the close, its log line. An RSA-2048 certificate makes a full
  handshake about 2.4 times as dear per connection (in a measurement with
  `curl`, which does not resume: 930 µs against 390 µs).

`v1.1.0`, measured by the earlier form of the load test (access log off,
RSA certificate), ran within noise of this version's previous build on kept
connections; the comparison is in the spec (Section 15).

### Sizing a node

- **Clients that reuse connections** (keep-alive, HTTP/2: the normal case)
  make a node request-bound: at about 70 µs of CPU per proxied request, a
  core serves some 14,000 of them per second, and the backends or the
  network saturate first.
- **Clients that open a connection per request** make it connection-bound:
  at about 280 µs of CPU per connection, a core serves some 3,500 of them
  per second with an ECDSA certificate, fewer than half that with RSA. This
  is the regime to size for, and why **ECDSA rather than RSA certificates**
  matter: an RSA-2048 signature costs several times an ECDSA P-256 one, an
  RSA-4096 one far more. Session resumption saves the client a round trip
  and the node little.
- **Pooled upstream connections.** Leave `[upstream] idle_per_host` unset.
  A cap below the requests in flight to a backend makes the pool close a
  connection on every response beyond the cap and dial a new one for the
  next request: with the earlier default of 32 and 64 concurrent clients,
  that was some 1,200 connects per second to one backend and 6 to 8% of
  the throughput.
- **Large uploads and many idle connections** are bound by bytes and by
  memory, not by request rate: bodies are streamed, never buffered whole, and
  an idle TLS connection costs memory and a file descriptor (the unit sets
  `LimitNOFILE=1048576`; `max_connections` defaults to 100,000).

Nodes are stateless, so capacity grows with their number: size a fleet so
that it carries its peak with one node missing, by its **connection rate**,
its **concurrent connections** and its **bytes**, rather than by requests
per second alone.

## Quick start

Building needs Rust (1.88 or later), a C compiler (for `ring`, the
cryptography under rustls) and, on Linux, `clang` (the eBPF program of the
kernel view; a Linux build fails without it).

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

A Cargo workspace at the root of the repository: the libraries in `lib/`,
the product in `gfe/`, and each crate named after what it does.

```
lib/                     netkit: building blocks for networked systems, knowing nothing about GFE
  http/                  netkit-http             HTTP/1.1 and HTTP/2, serving and requesting
  tls/                   netkit-tls              TLS termination and origination, the certificate store
  dns/                   netkit-dns              Host names to addresses, cached
  load-balancing/        netkit-load-balancing   Pools and selection policies
  health-checking/       netkit-health-checking  Probes, the per-backend state machine, the checker
  rate-limiting/         netkit-rate-limiting    Caps on what is in use at once and how often
  listen/                netkit-listen           Listening sockets, accept loops, draining, handover
  kernel/                netkit-kernel           The eBPF view of TCP connections (bpf/: the program)
  observability/         netkit-observability    Prometheus metrics, the log that never blocks
gfe/                     GFE, the product
  config/                gfe-config              The two config files: schema, loading, validation
  proxy/                 gfe-proxy               The reverse proxy: the edge, routing, the request
                                                 handler, keeping in step with the config, metrics
  node/                  gfe-node                The binary: CLI, wiring, signals, the ops endpoints,
                                                 upgrade in place

distribution/            What ships besides the binary
  systemd/               The unit of gfe-node
  docker/                The image of gfe-node
  grafana/               Prebuilt dashboard
  prometheus/            Alerting rules (GFE + host network)
docs/                    Specification, guides, and the example configs
hack/
  loadtest/              gfe-loadtest: load generator for benchmarks (not shipped)
  loadtest.sh            End-to-end load test of the real binary
  create-tag.sh          Tag a release, listing the commits since the last one
  demo/                  Local playground: node, backends, traffic, monitoring
  rpm/                   What the RPM runs when installed and removed
```

Dependencies go one way: `gfe-node` → `gfe-proxy` → `gfe-config` and the
netkit libraries. No library depends on a `gfe-*` crate. No crate contains
`unsafe`.

## Development

```bash
cargo test --workspace          # unit + functional tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo deny check                # advisories, licenses, sources
```

Tests are the only thing that stands between a change and a regression.
Unit tests sit next to the code (`foo.rs` has its tests in `foo_test.rs`),
functional tests are in each crate's `tests/`, one file per feature, and
the tests of the binary in `gfe/node/tests/` start `gfe-node` as an
operator would. [`docs/requirements.md`](docs/requirements.md) maps every
feature listed above to the tests that fail when it breaks, and a test
keeps that map true.

Whether a change made the node slower is measured against the commit it
is based on, on the same machine, by the end-to-end load test; the `perf`
workflow runs it on every pull request:

```bash
./hack/loadtest.sh --against main   # the real binary of each, compared on CPU per request
cargo bench -p gfe-proxy --bench routing        # where in the node: criterion micro-benchmarks
```

The [testing guide](docs/testing.md) describes the suite, the requirements
map, the load test and the benchmarks, and how to read them.

## Documentation

- **[Specification](docs/spec.md)** — architecture and behaviour, in detail.
- **[Requirements](docs/requirements.md)** — each feature and the tests that prove it.
- **[Testing guide](docs/testing.md)** — what a change has to prove, and how.
- **[Observability guide](docs/observability.md)** — which signal answers which question.
- **[Demo guide](docs/demo.md)** — the local playground and what to try in it.
- **[RPM guide](docs/rpm.md)** — building the package and managing a node with Puppet.

## License

MIT
