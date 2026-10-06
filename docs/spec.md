# General Front End (GFE) — Design Specification

> Inspired by Google's Front End (GFE) service. This document specifies **General Front End**, a Rust-implemented, L7 TLS-terminating HTTP reverse proxy built on its own networking libraries (netkit): what a node does, in which order, and why, precisely enough to operate it and to change it.

---

## Table of Contents

1. [Goals and Non-Goals](#1-goals-and-non-goals)
2. [Architecture Overview](#2-architecture-overview)
3. [Project Structure](#3-project-structure)
4. [Request Model](#4-request-model)
5. [Request Flow](#5-request-flow)
6. [Proxy Design (Data Plane)](#6-proxy-design-data-plane)
   - 6.1 [Listeners and Acceptors](#61-listeners-and-acceptors)
   - 6.2 [TLS Termination and SNI Certificate Resolution](#62-tls-termination-and-sni-certificate-resolution)
   - 6.3 [HTTP Protocol Handling](#63-http-protocol-handling)
   - 6.4 [Routing](#64-routing)
   - 6.5 [Upstream Selection and Load Balancing](#65-upstream-selection-and-load-balancing)
   - 6.6 [Upstream Connection Pooling](#66-upstream-connection-pooling)
   - 6.7 [Request and Response Forwarding](#67-request-and-response-forwarding)
   - 6.8 [Timeouts, Retries, and Limits](#68-timeouts-retries-and-limits)
7. [Controller Design (Control Plane)](#7-controller-design-control-plane)
   - 7.1 [L7 Health Checking](#71-l7-health-checking)
   - 7.2 [Config Manager](#72-config-manager)
   - 7.3 [Certificate Manager](#73-certificate-manager)
   - 7.4 [Lame Duck and Graceful Drain](#74-lame-duck-and-graceful-drain)
8. [Configuration Model](#8-configuration-model)
9. [TLS Policy](#9-tls-policy)
10. [Upstream Requirements](#10-upstream-requirements)
11. [Observability](#11-observability)
12. [Failure Modes and Resilience](#12-failure-modes-and-resilience)
13. [Operational Considerations](#13-operational-considerations)
14. [What Is Not There](#14-what-is-not-there)
15. [Differences from v1.1.0](#15-differences-from-v110)
16. [Technology Stack](#16-technology-stack)

---

## 1. Goals and Non-Goals

### Goals

- Provide a **centralized, shared L7 reverse-proxy and TLS-termination service** for all teams, so individual teams never manage certificates, TLS policy, or HTTP edge concerns themselves.
- **Terminate TLS** on behalf of every service behind a shared set of addresses, with **SNI-based certificate selection** from a centrally managed certificate store.
- Enforce a **uniform TLS policy** (minimum protocol version, approved cipher suites, HSTS) centrally, so security posture is consistent across all services.
- **Route HTTP requests** to the correct upstream pool based on the SNI / `Host` header and request path.
- Maintain **long-lived, pooled upstream connections** to application backends, amortizing TLS handshake and TCP setup cost across many client requests.
- Perform **L7 health checking** (HTTP/HTTPS/gRPC) of upstreams and route only to healthy upstreams.
- Support **zero-downtime backend deploys** via lame-duck draining: an upstream signals readiness to drain and GFE stops sending it new requests while in-flight requests complete.
- Be **fully stateless**: a GFE node's behaviour is a pure function of its configuration. Any node can be added, removed, or restarted without coordination.
- Be **configured entirely from a local file**, hot-reloaded atomically.
- Expose **rich metrics and structured logs** for monitoring.
- Be **minimal**: implement only the features that genuinely add value as a shared edge. No knobs that a single team could trivially manage themselves.

### Non-Goals

- GFE is **not an L4 load balancer**. Spreading client traffic across GFE nodes is the job of whatever sits in front of them (an L4 load balancer, DNS, anycast). GFE does not speak BGP and does not do packet forwarding.
- GFE is **not a kernel-bypass data plane**. GFE terminates TCP and TLS and therefore uses the kernel network stack and ordinary async sockets. There is no AF_XDP path.
- GFE is **not a WAF or DDoS scrubber**. It performs basic edge hygiene (connection/header limits, timeouts) but is not a security inspection engine.
- GFE is **not a CDN / cache**. It does not store response bodies.
- GFE does **not host application logic**. It proxies; it does not serve content beyond minimal synthetic error responses and its own health/metrics endpoints.
- GFE is **not a service mesh sidecar**. It is a centralized fleet, not a per-pod proxy.
- GFE does **not own certificate issuance**. It consumes certificates from files that deployment tooling writes; issuance, renewal and CA trust decisions live elsewhere.

---

## 2. Architecture Overview

A GFE node terminates TLS for clients and proxies their HTTP requests to application backends. A node does not care how traffic reaches it: an L4 load balancer, DNS or anycast may spread clients over a fleet of nodes, or clients may connect to one directly. Nothing in GFE assumes one or the other. Whatever sends traffic to a node should probe its `/readyz` (Section 11.3), which fails while the node drains.

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

**The protocols are the netkit libraries'.** GFE is built on a set of libraries of its repository (`lib/`), each of which does one job and knows nothing about GFE. HTTP/1.1 and HTTP/2 on both legs are `netkit-http`'s, with hyper and h2 underneath: its server serves each established client connection and holds it to the client timeouts and to the drain, and its pooled client carries requests to backends. TLS in both directions is `netkit-tls`'s, on rustls. The listening sockets, the accept loops, the connection limits, draining and the handover of sockets to a successor are `netkit-listen`'s. The libraries report what happened (why a connection ended, why a handshake or an exchange with a backend failed) through return values and small traits, and GFE turns that into its metrics and log events.

**GFE is what joins them** (`gfe-proxy`). Its edge serves every connection `netkit-listen` accepts: socket options, TLS termination under its timeout, HTTP held to the node's settings, and the accounting of the connection. It hands every request to the request handler, which decides the host, the route and the backend, forwards the request, bounds the wait for the backend, retries what may be retried, and reports the request. The edge and the handler know each other only through a trait (`RequestHandler`) and what a request knows of its connection (`ConnInfo`). The process around them (the command line, signals, the ops endpoint, the upgrade in place) is `gfe-node`'s.

A GFE node has two logical components:

- **Proxy (data plane).** Accepts client connections, terminates TLS, serves HTTP on them, selects a route and an upstream backend, and proxies the request/response over a pooled upstream connection. Fully async (Tokio).
- **Controller (control plane).** Watches the config file, validates and atomically swaps in new configuration, reconciles the listening sockets, health-checks upstreams, manages the certificate store, and drives lame-duck draining.

The two communicate only through **atomic pointer swaps** (`ArcSwap`) of the shared routing/upstream snapshot and certificate store, and a shared health status map. There is no other shared mutable state, and there is no coordination between GFE nodes.

---

## 3. Project Structure

The codebase is a Cargo workspace at the root of the repository. The libraries are in `lib/`, the product in `gfe/`, and each crate is named after what it does: a reader should guess where a thing lives before opening the tree.

```
gfe/
├── Cargo.toml                          # Workspace root
├── Cargo.lock
├── deny.toml                           # Dependency policy, checked by cargo-deny
├── README.md
├── LICENSE
│
├── lib/                                # netkit: building blocks, knowing nothing about GFE
│   ├── http/                           # netkit-http: HTTP/1.1 and HTTP/2, serving and requesting
│   ├── tls/                            # netkit-tls: TLS termination and origination
│   ├── dns/                            # netkit-dns: host names to addresses, cached
│   ├── load-balancing/                 # netkit-load-balancing: pools, selection policies
│   ├── health-checking/                # netkit-health-checking: probes, state machine, checker
│   ├── rate-limiting/                  # netkit-rate-limiting: caps on use and on rate
│   ├── listen/                         # netkit-listen: sockets, accept loops, drain, handover
│   ├── kernel/                         # netkit-kernel: the eBPF view of TCP connections
│   └── observability/                  # netkit-observability: metrics registry, the log
│
├── gfe/                                # GFE, the product
│   ├── config/                         # gfe-config: the two config files
│   ├── proxy/                          # gfe-proxy: the reverse proxy
│   └── node/                           # gfe-node: the binary a node runs
│
├── distribution/                       # What ships besides the binary
│   ├── systemd/gfe-node.service        # systemd unit
│   ├── docker/Dockerfile               # The image of gfe-node
│   ├── grafana/gfe-dashboard.json      # Pre-built Grafana dashboard
│   └── prometheus/gfe-alerts.yml       # Alerting rules
│
├── docs/
│   ├── spec.md                         # This specification
│   ├── observability.md                # Metrics, logs, alerts and the dashboard
│   ├── demo.md                         # The local playground, and what to try in it
│   ├── rpm.md                          # Building the RPM; a node under Puppet
│   └── examples/
│       ├── gfe.example.toml            # Reference node (bootstrap) configuration
│       └── gfe-dynamic.example.json    # Reference dynamic configuration
│
└── hack/                               # Development tools, not shipped
    ├── loadtest/                       # gfe-loadtest: load generator for benchmarks
    ├── loadtest.sh                     # End-to-end load test of the real binary
    ├── create-tag.sh                   # Tag a release, listing what it brings
    ├── demo/                           # Local playground: node, backends, monitoring
    └── rpm/                            # What the RPM runs when installed and removed
```

The crates:

```
│  ─────────────────────────────────
│  THE LIBRARIES (lib/) — know nothing about GFE
│  ─────────────────────────────────
│
├── netkit-http/                     # lib/http
│   ├── tests/                       # client_*.rs, server_*.rs: against hyper and rustls peers
│   └── src/
│       ├── lib.rs                   # The `http` crate's vocabulary, re-exported
│       ├── body.rs                  # Request and response bodies
│       ├── server.rs                # Serving one connection: timers, drain, how it ended
│       ├── server/activity.rs       #   Whether a request is in flight; which timer is due
│       ├── client.rs                # Requesting
│       └── client/
│           ├── pool.rs              #   The pooled client, under one cap on connections
│           ├── connection.rs        #   One connection, no pool (health probes)
│           ├── dial.rs              #   Lookup, TCP, TLS, under one deadline
│           └── failure.rs           #   Why an exchange with a server failed
│
├── netkit-tls/                      # lib/tls
│   ├── benches/handshake.rs         # TLS handshakes per second
│   ├── tests/acceptor.rs  connector.rs
│   └── src/
│       ├── acceptor.rs              # The handshake: what it settled on, why it failed
│       ├── cert_store.rs            # SNI → certified key map, atomically swappable
│       ├── resolver.rs              # rustls ResolvesServerCert backed by the store
│       ├── policy.rs                # ServerConfig builder: versions, ALPN, resumption
│       ├── loader.rs                # PEM cert/key parsing, expiry extraction
│       ├── cert_files.rs            # Detects certificate files replaced in place
│       ├── connector.rs             # TLS towards servers: trust store, client certificate
│       ├── options.rs               # MinVersion, CertSpec: what a caller tells the crate
│       └── error.rs
│
├── netkit-dns/                      # lib/dns
│   └── src/cache.rs                 # The system resolver behind a cache
│
├── netkit-load-balancing/           # lib/load-balancing
│   ├── benches/selection.rs         # Selection throughput per policy
│   └── src/
│       ├── pool.rs                  # Pools: selection over the healthy set, max_in_flight
│       ├── policy.rs                # RoundRobin, LeastRequest, RingHash
│       └── error.rs
│
├── netkit-health-checking/          # lib/health-checking
│   └── src/
│       ├── checker.rs               # Runs probes, deduplicated by (host, port)
│       ├── probe.rs                 # Probe trait + TCP, HTTP(S) and gRPC probes
│       ├── state_machine.rs         # UNKNOWN → HEALTHY ↔ UNHEALTHY (+ DRAINING)
│       └── health_map.rs            # HealthStatus and the shared map of it
│
├── netkit-rate-limiting/            # lib/rate-limiting
│   └── src/
│       ├── concurrency.rs           # A cap on how many of something are in use
│       └── token_bucket.rs          # A cap on how often something happens
│
├── netkit-listen/                   # lib/listen
│   └── src/
│       ├── listeners.rs             # Listening sockets, reconciled against the config
│       ├── accept.rs                # Per-socket accept loop, connection limits
│       ├── drain.rs                 # Telling a process to drain
│       ├── keep_alive.rs            # TCP keepalive on a connection
│       ├── metered.rs               # Counting the bytes on the wire
│       └── handover.rs              # Passing listening sockets to a successor
│
├── netkit-kernel/                   # lib/kernel
│   ├── bpf/tcp_events.bpf.c         # The eBPF program (sockops, cgroup-attached)
│   ├── build.rs                     # Compiles it with clang (Linux builds)
│   ├── tests/kernel.rs              # Attaches it for real (Linux, privileged)
│   └── src/
│       ├── lib.rs                   # Types; why it may be unavailable
│       ├── wire.rs                  # Byte layouts shared with the program
│       ├── linux.rs                 # Load, attach, read
│       └── unsupported.rs           # Stand-in elsewhere
│
├── netkit-observability/            # lib/observability
│   └── src/
│       ├── lib.rs                   # The registry and its exposition
│       └── logging.rs               # The log: destinations, never blocking
│
│  ─────────────────────────────────
│  GFE (gfe/) — the product
│  ─────────────────────────────────
│
├── gfe-config/                      # gfe/config
│   ├── tests/examples.rs            # The example configs of docs/examples/ load
│   └── src/
│       ├── node.rs                  # NodeConfig (bootstrap TOML), deprecated keys
│       ├── dynamic.rs               # DynamicConfig (listeners, routes, pools, certificates)
│       ├── listener.rs              # Listener, ListenProtocol (http|https)
│       ├── route.rs                 # Route, RouteAction
│       ├── pool.rs                  # UpstreamPool, Upstream, LbPolicy, Scheme
│       ├── certificate.rs           # CertEntry
│       ├── health_check.rs          # HealthCheckConfig, ProbeType
│       ├── tls.rs                   # TlsConfig, MinVersion
│       ├── duration.rs              # Durations as "5s", "200ms"
│       ├── loader.rs                # Read and deserialize the files
│       ├── validator.rs             # Semantic validation
│       └── error.rs
│
├── gfe-proxy/                       # gfe/proxy
│   ├── benches/routing.rs           # Route match throughput
│   ├── tests/                       # A whole proxy in front of mock backends, one file per feature
│   │   ├── common/mod.rs            #   Mock backends and clients (hyper), certificates (rcgen)
│   │   ├── common/node.rs           #   A whole Frontend in a scratch directory
│   │   ├── connections.rs  tls.rs  routing.rs  forwarding.rs  grpc.rs  load_balancing.rs
│   │   ├── health.rs  retries.rs  timeouts.rs  limits.rs  upstream_tls.rs  errors.rs
│   │   └── reload.rs  drain.rs  kernel.rs  observability.rs
│   └── src/
│       ├── lib.rs
│       ├── frontend.rs              # Frontend: a running reverse proxy, everything put together
│       ├── edge/                    # Serving the connections of clients
│       │   ├── handler.rs           #   RequestHandler: what the edge asks of the handler
│       │   ├── conn_info.rs         #   ConnInfo: what a request knows of its connection
│       │   ├── connection.rs        #   Edge: one connection, socket options, TLS, HTTP
│       │   ├── conn_record.rs       #   Per-connection metrics and log event, the close reason
│       │   ├── listeners.rs         #   The node's listeners on netkit-listen
│       │   └── shared.rs            #   Shared: metrics, limits, timeouts, accept queue, SNI misses
│       ├── handler/                 # What happens to a request
│       │   ├── mod.rs               #   Proxy: the order of the steps
│       │   ├── state.rs             #   State: what every request reads; the upstream client
│       │   ├── host.rs              #   Which host a request is for (400 / 421)
│       │   ├── request.rs           #   Request id, gRPC, target form, upgrades, forwarding headers
│       │   ├── forward.rs           #   Quota, selection, sending, the response head
│       │   ├── progress.rs          #   When a backend is overdue
│       │   ├── retry.rs             #   What may be retried
│       │   ├── failure.rs           #   Why a request to a backend failed
│       │   ├── respond.rs           #   The answers GFE writes itself
│       │   ├── record.rs            #   Per-request metrics and access-log event
│       │   └── error.rs
│       ├── routing/                 # (listener, host, path) → route
│       │   ├── matcher.rs           #   Host (exact + wildcard) and path matching
│       │   └── table.rs             #   Compiled route table built from a config
│       ├── reload/                  # Keeping a node in step with its config
│       │   ├── applier.rs           #   Validate and compile snapshots, swap them in atomically
│       │   ├── controller.rs        #   Controller: start, reload, fall back, the certificate poll
│       │   ├── watcher.rs           #   notify (inotify) watcher on the config file
│       │   ├── health.rs            #   The health checks of a config; their metrics
│       │   ├── cache.rs             #   Last-known-good cache for restart resilience
│       │   └── error.rs             #   ReloadError
│       ├── metrics/                 # Every metric a node exports
│       │   ├── proxy.rs             #   Connections, TLS, requests, upstream requests, bytes
│       │   ├── control.rs           #   Health, config reload, upgrades, cert expiry
│       │   ├── process.rs           #   File descriptors, CPU, memory, runtime, the log
│       │   └── kernel.rs            #   What the kernel reports (eBPF)
│       └── kernel.rs                # The kernel view, as metrics and log events
│
└── gfe-node/                        # gfe/node
    ├── tests/                       # Tests that start the binary
    │   ├── common/mod.rs            #   Node: a real gfe-node process in a scratch directory
    │   ├── smoke.rs                 #   The whole product, from start to stop
    │   ├── check_config.rs  startup.rs  logging.rs  upgrade.rs
    │   └── kernel.rs                #   gfe_ebpf_attached, with and without the capabilities
    └── src/
        ├── main.rs                  # CLI args, wiring, the signal loop
        ├── ops.rs                   # /healthz, /readyz, /metrics
        ├── lib.rs                   # What the tests reach directly
        ├── signals.rs               # The signals a node acts on
        ├── systemd.rs               # sd_notify
        ├── upgrade.rs               # Replacing a running node in place
        └── handover.rs              # GFE's side of passing listening sockets to a successor
```

### Design Principles Behind the Structure

**Libraries That Know Nothing of GFE.** A library in `lib/` is named after its concern (`netkit-<concern>`) and is usable by any networked system: it does not depend on a `gfe-*` crate, read GFE's config, define a `gfe_` metric or emit GFE's log events. What it observes it returns (`Closed` from serving a connection, `HandshakeError::reason`, a client `Failure` of a `FailureKind`) or reports through a small trait the caller implements (`HealthObserver`, `Tally`), and the caller turns that into metrics and logs. Things that only make sense together stay modules of one crate rather than crates of their own.

**`gfe-proxy` Is the Reverse Proxy.** `gfe-proxy` joins the libraries into GFE: serving the connections of clients (`edge`), deciding which route a request takes (`routing`), what happens to a request (`handler`), keeping in step with the config (`reload`), the kernel view (`kernel`), and every metric a node exports (`metrics`). `Frontend` (`frontend.rs`) puts them together into a running reverse proxy; the binary adds the process around it (command line, signals, the ops endpoint, the upgrade in place), and the functional tests drive the same `Frontend`, so that they test what a node runs.

**Third-Party Code Is Confined.** The protocols are hyper (with h2) and rustls, on tokio. hyper and the HTTP crates around it are named, in a manifest's `[dependencies]`, by `netkit-http` alone, and rustls by `netkit-tls` alone; everything else reaches them through those libraries, which re-export the vocabulary types (`Request`, `Response`, `StatusCode`, ...) as they are. The other crates with one job are confined the same way: `aya` to `netkit-kernel`, `socket2` to `netkit-listen`, `prometheus-client` and `tracing-subscriber` to `netkit-observability`. There is no framework above them. The reason is the owner's: "We don't want to depend on any other library (high level one) in this project. We need to reduce the dependency risks." Section 16 lists who names what.

**Dependencies Go One Way.**

```
netkit-dns  netkit-tls  netkit-rate-limiting  netkit-kernel  netkit-observability
                                  use nothing from the workspace
netkit-listen           → rate-limiting
netkit-http             → dns, tls, rate-limiting
netkit-health-checking  → http, tls
netkit-load-balancing   → health-checking
gfe-config              (nothing from the workspace)
gfe-proxy               → gfe-config and the libraries
gfe-node                → gfe-proxy (and what it needs below)
gfe-loadtest            (nothing: a development tool)
```

`gfe-node` is the only binary a node runs.

**Nothing Is Published.** Nothing in the workspace is published to crates.io (`publish = false`): the libraries are used from this repository.

**No `unsafe`.** `unsafe_code = "forbid"` is a workspace lint. What needs it (system calls, socket options, eBPF maps) goes through crates whose job that is (`rustix`, `socket2`, `aya`). The kernel program is C, checked by the kernel's verifier before it runs.

**Stateless by Construction.** No GFE crate persists request, session, or connection state across process restarts. The certificate store, route table, and upstream health are all derived from configuration plus live probing. Connection pools are ephemeral, per-node optimizations. This is what makes a GFE node interchangeable with any other.

**Atomic, Lock-Free Config Swaps.** The live routing snapshot and certificate store are held behind `ArcSwap`. A config reload compiles a brand-new snapshot off the hot path, then swaps the pointer in a single atomic store. In-flight requests keep using the old snapshot until they complete; new requests pick up the new one. The data plane never blocks on the control plane.

**Tests Live Close to What They Test.** Unit tests sit next to the code: `foo.rs` has its tests in a sibling `foo_test.rs` (`mod.rs` in `mod_test.rs`, `lib.rs` in `lib_test.rs`). Functional tests are in each crate's `tests/` directory, one file per feature; those of `gfe-proxy` run a whole proxy in-process, with real TLS termination, in front of mock backends. Tests that start the binary are in `gfe/node/tests/`. Benchmarks use `criterion` and sit in the crate they measure. The tests, the benchmarks and `gfe-loadtest` use hyper and rustls directly, as an independent client and server on the other side of the wire.

---

## 4. Request Model

GFE's configuration is built from four primitives.

### Listeners

A **listener** binds an address and port and accepts client connections.

- `protocol`: `https` (TLS-terminating) or `http` (plaintext — used for HTTP→HTTPS redirect listeners, internal-only addresses, or cleartext gRPC).
- For `https` listeners, a `TlsPolicy` and the certificate store apply.
- The bind address is any address of the node, or a wildcard (`0.0.0.0`, `::`); a `::` listener also accepts IPv4 clients where the system allows it.

### Routes

A **route** maps an incoming request to an action.

- **Match** on:
  - `host`: exact (`api.example.org`), single-label wildcard (`*.example.org`), or `*` for any host. The request's host is the authority of its target (`:authority` on HTTP/2, an absolute-form target on HTTP/1.1), else its `Host` header, else the SNI; it is checked as described under Normalization (Section 6.3).
  - `path_prefix`: prefix (`/api/`) or exact (`/healthz`). Most specific match wins (longest path prefix, exact host over wildcard).
- **Action**: forward to a named **upstream pool**, or return a fixed redirect (e.g. HTTP→HTTPS) or a fixed status.
- Routes are evaluated against a compiled, immutable `RouteTable` snapshot for O(1)–O(log n) matching.

### Upstream Pools

An **upstream pool** is a named set of application backends serving the same role.

- Each **upstream** is `host:port` plus optional `weight` (relative, default 1, at most 1000). `host` is a hostname or an IP literal, an IPv6 address written without brackets (`"2001:db8::1"`); GFE brackets it where a URI needs it. A hostname is resolved when a request is sent to it and the answer kept for 10 s; when a refresh fails, the previous answer is used. The first address is used. A `ring_hash` pool places 160 ring points per unit of weight and may hold at most 1,000,000 of them (sum of its weights at most 6250); a config beyond either limit is rejected.
- `scheme`: how GFE talks to the pool's backends, independent of the client-facing protocol: `http` (cleartext HTTP/1.1), `https` (TLS; HTTP/1.1, or HTTP/2 by ALPN for gRPC calls) or `h2c` (cleartext HTTP/2 with prior knowledge, for backends that speak only HTTP/2 without TLS, typically gRPC servers).
- `lb_policy`: how requests are distributed across healthy upstreams (Section 6.5).
- `health_check`: L7 probe config (Section 7.1).
- `max_in_flight` (optional, at least 1): the most requests the node may have in flight to the pool at once, counted from backend selection until the response has been relayed to its end or abandoned (the span of `gfe_upstream_requests_in_flight`). A request beyond it is answered `503` (`error=upstream_pool_full`, `UNAVAILABLE` to a gRPC caller) without being retried, and counted in `gfe_upstream_pool_full_total{pool}`. It keeps one slow pool from holding every connection `max_upstream_connections` allows, at the expense of the other pools. Absent: no quota. A reload that changes the pool starts the count afresh.
- Pools may be **referenced by multiple routes**. Health checks are deduplicated across pools by `(host, port)`.

### Certificates

A **certificate** entry binds one or more SNI names to a PEM certificate chain + private key on disk.

- Supports exact names and single-label wildcards (`*.example.org`).
- An optional `default` certificate handles connections whose SNI matches nothing (or clients that send no SNI).
- Certificates are loaded into the in-memory cert store and watched for change (Section 7.3).

---

## 5. Request Flow

```
 1. A client opens a TCP connection to a listener's address. How it got there
    (an L4 load balancer, DNS, anycast, or directly) makes no difference.
 2. The accept loop (netkit-listen) accepts it, subject to the connection
    limits, and spawns one task for it, which the edge serves (gfe-proxy: edge).
 3. The connection (edge/connection.rs) sets TCP_NODELAY and TCP keepalive,
    and its record starts (edge/conn_record.rs).
 4. On an https listener, the TLS handshake (netkit-tls), within tls_handshake:
    a. ClientHello arrives; the SNI resolver (resolver.rs) selects a certificate
       from the cert store (cert_store.rs) by SNI, falling back to default.
    b. The TLS policy (policy.rs) enforces the minimum version; ALPN
       negotiates h2 or http/1.1.
 5. The connection is served by netkit-http's server, HTTP/1.1 or HTTP/2. It
    hands each request to GFE's request handler (gfe-proxy: handler), with
    what is known of its connection (ConnInfo):
    a. The host is checked (host.rs) and the request routed (routing/): match
       (listener, host, path) → action.
       - No match → 404 synthetic response (respond.rs).
       - Redirect/fixed action → respond directly.
       - Forward action → continue.
    b. Upstream selection (netkit-load-balancing): from the route's pool, pick a
       healthy backend via the pool's LB policy.
    c. Connection acquisition (netkit-http's pooled client): reuse a pooled
       idle connection to the backend or open a new one (its name looked up
       through netkit-dns, TLS by netkit-tls if scheme=https), within
       max_upstream_connections.
    d. Forwarding (request.rs, forward.rs): strip hop-by-hop headers, add
       forwarding headers (X-Forwarded-For/-Proto/-Host, Forwarded,
       X-Request-Id), stream the request body to the upstream, bound the wait
       for the response head (progress.rs), stream the response body back to
       the client.
    e. The request is reported once (record.rs): metrics and a gfe::access event.
 6. Connection reuse: the client's keep-alive / h2 connection is retained; the
    upstream connection is returned to the idle pool for the next request.
 7. When the connection ends, it is reported once (conn_record.rs): metrics,
    the close reason, and a gfe::conn event.
```

---

## 6. Proxy Design (Data Plane)

> **Code location:** `gfe/proxy/src/edge/` (the edge), `gfe/proxy/src/handler/` (the request path), `gfe/proxy/src/routing/`, `lib/http/`, `lib/tls/`, `lib/listen/`, `lib/load-balancing/`

The proxy is a fully asynchronous Tokio service. It terminates TCP and TLS and therefore uses the kernel stack and ordinary `tokio::net` sockets — there is no kernel bypass and no per-packet hot path to keep allocation-free. The performance discipline instead targets **per-request** overhead: streaming bodies, connection reuse, and lock-free config reads.

The request handler (`Proxy`, `gfe/proxy/src/handler/mod.rs`) answers every request it is handed, in this order: the host the request is for (`host.rs`); the start of its record, from which it counts as in flight (`record.rs`); the route that matches its listener, host and path (`routing/`); and the route's action, either an answer GFE writes itself (`respond.rs`) or a forward to a pool (`forward.rs`), which shapes the request for the backend (`request.rs`), bounds the wait for it (`progress.rs`), says why it failed (`failure.rs`) and retries what may be retried (`retry.rs`). Routes and pools are read from one snapshot per request.

Why a request to a backend failed is logged at debug level under the target `gfe::proxy`, with the backend; the request's `gfe::access` event says it in one word (`error`).

### 6.1 Listeners and Acceptors

> **Code location:** `lib/listen/src/listeners.rs`, `lib/listen/src/accept.rs`, `gfe/proxy/src/edge/listeners.rs`, `gfe/proxy/src/edge/connection.rs`

One accept loop runs per configured listener. Each loop:

1. Binds the listener address (`TcpListener`) with `SO_REUSEADDR`; `TCP_NODELAY` and TCP keepalive (Section 6.8) are set on accepted sockets.
2. Accepts connections and enforces a **global and per-listener max concurrent connection limit**. When the limit is hit, new connections are accepted and immediately closed (counted via `gfe_connections_rejected_total{reason="limit"}`) rather than being left to pile up in the backlog.
3. Spawns one Tokio task per accepted connection (`connection.rs`). The accept loop never blocks on per-connection work. After a failed `accept` it waits 100 ms before accepting again (still stopping at once on shutdown), so an error that persists, such as running out of file descriptors, neither spins a core nor floods the log.
4. Applies an **accept-to-first-byte / handshake timeout** so slow-loris-style connections that never make progress are reaped early.

Client addresses are recorded in canonical form: an IPv4 client of a `::` listener is `1.2.3.4`, not `::ffff:1.2.3.4`, in the logs, in what a request knows of its connection, and in the kernel view.

The set of active listeners is part of the config snapshot and is reconciled on every reload (`listeners.rs`). A listening socket is identified by its **address and port**; a listener's protocol is read per accepted connection and its id per request, so they can change without rebinding (a renamed listener's open connections are routed by the new id). On reload:

- sockets for addresses the new config adds are bound **first** — if any cannot be bound the whole reload is rejected and nothing changes;
- sockets the new config no longer names stop accepting (connections already accepted on them run to completion);
- sockets whose address is unchanged are left untouched, so a reload never causes an accept gap.

Two listeners may not share an address and port (rejected by validation).

### 6.2 TLS Termination and SNI Certificate Resolution

> **Code location:** `lib/tls/`

GFE terminates TLS with **rustls**, through `netkit-tls`, in the edge and before any HTTP is spoken: a failed handshake is counted by reason and logged, and the connection ends there. Centralized certificate management is GFE's core value proposition.

**Certificate store (`cert_store.rs`).** An immutable map from SNI name → `Arc<CertifiedKey>` (parsed chain + signing key), plus an optional default. Wildcard names (`*.example.org`) are matched after exact names. The store is held behind `ArcSwap`; the certificate manager (Section 7.3) builds a new store and swaps it atomically, so a cert rotation never interrupts in-flight handshakes.

**SNI resolver (`resolver.rs`).** Implements rustls's `ResolvesServerCert`. On each `ClientHello` it reads the current store (a single atomic load), looks up the SNI, and returns the certified key. Lookup order: exact SNI → wildcard SNI → default cert. A miss is counted (`gfe_tls_sni_no_cert_total`) and the handshake is failed cleanly.

**TLS policy (`policy.rs`).** Builds the rustls `ServerConfig`: minimum protocol version (default TLS 1.2, configurable to 1.3-only), rustls's cipher-suite / signature-scheme set with the `ring` provider, session resumption, and ALPN advertisement (`h2`, `http/1.1`). See Section 9.

**Session resumption.** TLS 1.2 tickets and TLS 1.3 PSK use a per-node rotating ticketer, which speeds up reconnects to the *same* node. A client whose new connection lands on another node makes a full handshake, which is correct but costs CPU. Fleet-shared ticket keys (`[tls] ticket_key_file`) are accepted in the config but not used yet (Section 14).

**Closing.** A TLS connection the node closes, including one it gives up on (a request head that never came, a connection cut at the drain deadline), is closed with a `close_notify`, so that the client can tell an orderly end from a connection cut short.

### 6.3 HTTP Protocol Handling

> **Code location:** `lib/http/src/server.rs`, `gfe/proxy/src/edge/connection.rs`, `gfe/proxy/src/handler/host.rs`

After the handshake, the connection is served by **`netkit-http`'s server** (hyper underneath), through a stream that counts the bytes on the wire:

- **Downstream protocols:** HTTP/1.1 and HTTP/2. On HTTPS listeners the version is selected by ALPN; plaintext listeners detect HTTP/2 by its connection preface (prior knowledge), which is what cleartext gRPC clients use. HTTP/1.0 is accepted but kept alive only when the client opts in.
- **Keep-alive / multiplexing:** h1 keep-alive and h2 multiplexing are honored; each request on the connection is routed independently. The streams of an HTTP/2 connection are served concurrently, so one slow request does not hold up the others.
- **Limits:** max header size, max concurrent h2 streams, and request/idle timeouts are enforced per connection (Section 6.8).
- **What the HTTP layer answers itself.** Some requests never reach GFE's request handler, and therefore have no `gfe::access` event, no `X-Request-Id`, and are in no per-request metric: an HTTP/1.1 request with a malformed head is answered `400`, and one whose head is over `max_header_bytes` is answered `431`, and the connection is closed. The connection's `gfe::conn` event still records it, as `protocol_error`.
- **Normalization:** before routing, the request's host is checked (`host.rs`), and GFE answers itself when it fails:
  - a request whose target authority (`:authority`, or an absolute-form target) and `Host` header name different hosts, or different ports when both carry one, gets a `400` (`host_conflict`). Hosts are compared as hosts: `GET http://Public.example.org:80/` with `Host: public.example.org` is served;
  - a request with no host at all (no target authority, no valid `Host` header, no SNI) gets a `400` (`host_missing`). The exception is an HTTP/1.0 request, since HTTP/1.0 has no `Host` header to require: it is for no host in particular, and only a catch-all (`*`) route matches it. Simple health probes are such requests;
  - on HTTPS, a request for another host than the SNI is served only if the certificate store resolves both names to the same certificate entry (the default one included), as a client coalescing HTTP/2 connections does; otherwise it gets a `421 Misdirected Request` (`misdirected_request`), which tells the client to retry on a new connection.

### 6.4 Routing

> **Code location:** `gfe/proxy/src/routing/`

Routing maps a request to an action using a compiled, immutable snapshot.

- The `RouteTable` (`table.rs`) is compiled from `DynamicConfig` at reload time: host matches are bucketed (exact map + wildcard list), and within a host, paths are stored for **longest-prefix / exact** resolution.
- Match precedence: exact host beats wildcard host; within a host, exact path beats the longest matching prefix.
- The table is read via `ArcSwap` — a single atomic load per request, no lock.
- A non-match returns a synthetic `404` (`respond.rs`). A matched `Redirect` or `Fixed` action is answered directly without touching an upstream (this is how HTTP→HTTPS redirect listeners work).

### 6.5 Upstream Selection and Load Balancing

> **Code location:** `lib/load-balancing/src/pool.rs`, `lib/load-balancing/src/policy.rs`

Once a route resolves to a pool, GFE selects one **healthy** upstream. The pool exposes only the current healthy set (driven by the health checker, Section 7.1); draining upstreams (lame duck, Section 7.4) are excluded from new selection.

Supported policies (minimal but sufficient):

| Policy | Use case |
|---|---|
| `round_robin` (default) | Even distribution across equal backends; a random pick in proportion to the weights when they differ. |
| `least_request` | Prefer the backend with the fewest in-flight requests per unit of weight; better under heterogeneous request cost. |
| `ring_hash` | Consistent hash of the client's IP address, for **session affinity**. A ketama-style ring, so backend changes disturb minimal traffic. |

If a pool has **no healthy upstreams**, GFE returns `503` and increments `gfe_no_healthy_upstream_total`.

### 6.6 Upstream Connection Pooling

> **Code location:** `lib/http/src/client/pool.rs`, `lib/http/src/client/dial.rs`, `lib/tls/src/connector.rs`, `gfe/proxy/src/handler/state.rs`

Long-lived pooled upstream connections are a primary reason to run a shared edge: they amortize TCP + TLS handshake cost across all client requests to a backend. The pool is `netkit-http`'s client (hyper-util's pool underneath).

- **Per-backend idle pools.** Keyed by scheme and `host:port`. Idle connections are reused; the pool keeps at most `[upstream] idle_per_host` idle connections per backend (unset or `0`: 32), and closes a connection idle for `[upstream] idle_timeout` (default `60s`), so connections to a backend that is no longer used (removed, or dead) do not linger and count against `max_upstream_connections`.
- **HTTP/1.1 and HTTP/2 upstreams.** HTTP/2 upstream connections (gRPC calls to `https` pools via ALPN, or `h2c`) are multiplexed: many concurrent requests share one connection per backend, subject to the backend's `SETTINGS_MAX_CONCURRENT_STREAMS`. For h1, one request per connection at a time.
- **Opening a connection.** The backend's name is looked up through the system's resolver (`netkit-dns`), and the answer trusted for 10 s; when a lookup fails, the last answer is kept. TCP is connected with `TCP_NODELAY`, then TLS is run for an `https` pool. `upstream_connect` bounds the three together.
- **Upstream TLS (`connector.rs`).** When `scheme=https`, GFE verifies the upstream certificate and its hostname against the system's trust store, plus `[upstream] extra_ca_file` when set. A system root that cannot be parsed is skipped, and a system store that cannot be read is a warning at startup, not a failure. Optional mTLS (`[upstream] client_cert_file` / `client_key_file`, a client certificate shown to upstreams) is supported for zero-trust backends.
- **Health and pooled connections.** When a backend transitions to UNHEALTHY or DRAINING, no new request is sent to it. Its idle pooled connections are not closed at once; they are closed after `[upstream] idle_timeout`.
- **A connection the backend had just closed.** A request that fails on a pooled connection the backend had closed in the meantime, before any of it was sent, is sent again on another connection, whatever its method.
- **Bounded.** Open upstream connections are capped node-wide at `max_upstream_connections`, to protect both GFE and the backends from connection storms after a reload or failover. The cap is enforced where connections are opened: a request that finds a pooled connection is unaffected, one that would need a new connection beyond the cap is answered at once with a `503` (`error=upstream_connection_limit`), without retrying and without counting against the backend. Connections are counted from the moment one starts being opened until its socket closes, idle ones included; `gfe_upstream_connections` shows that count.

### 6.7 Request and Response Forwarding

> **Code location:** `gfe/proxy/src/handler/request.rs`, `gfe/proxy/src/handler/forward.rs`

Forwarding streams bodies without buffering them in full:

- **Hop-by-hop headers** (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade`, `TE`, `Proxy-*`, etc.) and the headers `Connection` names are stripped per RFC 9110, from requests and responses, whatever they name: a forwarding header the client named is stripped and GFE sets its own. The one exception is a `TE` of exactly `trailers`, which is passed on: GFE does relay trailers, and gRPC requires the header.
- **Protocol upgrades are not supported**, WebSocket included. A request asking for one (`upgrade` among its `Connection` options, and an `Upgrade` header) is answered `501` (`error=upgrade_not_supported`) before any backend is selected, rather than being forwarded as a plain request with its upgrade headers stripped. The exception is an offer to switch to HTTP/2 (`Upgrade: h2c`, which `curl --http2` sends to a cleartext URL): the client does not depend on it, so the offer is dropped and the request served over HTTP/1.1. WebSocket over HTTP/2 (extended `CONNECT`) is refused as a request target that is not a path.
- **Forwarding headers** are added/normalized: `X-Forwarded-For` (append client IP), `X-Forwarded-Proto`, `X-Forwarded-Host`, `Forwarded`, and a generated `X-Request-Id` (propagated if the client supplied a valid one) for end-to-end tracing. The `X-Request-Id` is also put on the response the client gets when the backend did not set one. GFE adds no `Via`.
- **`Host`.** As with HAProxy, the backend receives the host the client asked for, whatever protocol the client spoke: the `Host` header of an HTTP/1.x request, or the `:authority` of an HTTP/2 one, port included if the client sent one. This is why requests to `http` and `https` pools go out over HTTP/1.1. A request that needs HTTP/2 (a gRPC call to an `https` pool, or any request to an `h2c` pool) is sent with `:authority` set to the backend's own `host:port` and without a `Host` header, which would contradict it. `X-Forwarded-Host` and `Forwarded` carry the client's host in every case.
- **Streaming.** Request and response bodies are streamed, so large uploads/downloads do not consume proportional memory. Backpressure flows naturally through the async body.
- **Request targets.** Only a target naming a path (origin form `/path`, or absolute form `http://host/path`) is forwarded. The asterisk form of `OPTIONS *` and the authority form of `CONNECT` are answered `400` (`error=unsupported_request_target`) before any backend is selected.
- **HSTS** (`Strict-Transport-Security`) is added, per TLS policy, to the responses relayed from backends to clients connected over HTTPS.
- **Protocol translation.** Client h2 ↔ upstream h1 (and vice versa) is handled at the request/response level: the handler sees requests and responses, not how they travel.
- **gRPC.** A gRPC call is an HTTP/2 request whose status travels in the response trailers, so it needs HTTP/2 on both legs and nothing buffered in between. GFE proxies unary and streaming calls (client-, server- and bidirectional) when the client connects over HTTP/2 and the pool's scheme is `https` (the backend selects `h2` by ALPN) or `h2c` (Section 4). Messages are relayed frame by frame in both directions and trailers are passed through. gRPC calls are `POST`s, so they are never retried, and they are not subject to the response timeouts (Section 6.8). When GFE itself fails a call (no route, no healthy upstream, backend unreachable, connection limit) it answers in gRPC's terms: a trailers-only response, HTTP `200` with `grpc-status` and a `grpc-message` of `gfe: <reason>`, the reason being the access log's `error` value. The status is the one gRPC's HTTP mapping assigns to the HTTP status GFE would otherwise have sent: `UNIMPLEMENTED` (12) for an unrouted call, `UNAVAILABLE` (14) for everything a `502`/`503`/`504` stands for. Such calls therefore count as `status="200"` in `gfe_requests_total` and by their `grpc_status` in `gfe_grpc_responses_total`.

### 6.8 Timeouts, Retries, and Limits

> **Code location:** `gfe/proxy/src/handler/progress.rs`, `gfe/proxy/src/handler/forward.rs`, `gfe/proxy/src/handler/retry.rs`, `gfe/proxy/src/edge/connection.rs`, `lib/http/src/server.rs`

Bounded, predictable behaviour under stress:

- **Timeouts:** TLS handshake, request header, upstream connect, upstream first-byte, and overall request timeouts — all configurable, with safe defaults.
- **Upstream timeouts (`progress.rs`, `forward.rs`).** Three timeouts bound the wait for a backend's response headers; none of them ever cuts a response that has started:
  - `upstream_connect` — opening the connection: the name lookup, the TCP connection and, for an `https` pool, its TLS handshake, together.
  - `upstream_first_byte` — per attempt: the backend must start responding within this long of having last been sent something, be it the request or a piece of its body. An upload therefore never times out while it progresses, whatever the pool's scheme. If the wait expires while GFE is waiting for the client to send more of the body (it last asked the client for more and got nothing), it is the client that stalled: it gets a `408` (`error=request_body_timeout`) and the backend is not counted as failing. Otherwise, including when the backend stopped taking the body (GFE asks the client for more only once the backend has taken what came before), the client gets a `504` and the backend is counted as having timed out (`kind="timeout"`).
  - `request_total` — across attempts: once the request has been sent in full, a response must arrive within this long, however many backends are tried.

  A client that leaves in the middle of its upload ends the request as `499` (`termination=client_abort`), with the bytes it had sent; nothing is counted against the backend.

  **gRPC calls are exempt** from `upstream_first_byte` and `request_total`: a streaming call may have nothing to send, not even headers, for as long as it likes. How long a call may take is the deadline its client sets (`grpc-timeout`, which GFE forwards) and enforces by cancelling. What the timeouts would have caught, a backend that died, is caught by **HTTP/2 keep-alive** on the upstream connection instead: a connection with requests in flight that has been silent for `upstream_first_byte` is pinged, and if the ping is not answered within `upstream_connect` the connection is closed and its calls fail.
- **Client timeouts (`lib/http/src/server.rs`, `edge/connection.rs`).** A request is *in flight* from its parsed head until its response body is fully written or dropped. Two timeouts are derived from that:
  - `request_header` — the **first** request head must arrive within this long of the connection being established (after the TLS handshake), else the connection is closed (`header_timeout`). This bounds connections that never send, or drip, a request. A head that arrived in time is served even when the node, short of CPU, looks at it after `request_header` has passed.
  - `client_idle` — a connection with **no request in flight** for this long is shut down gracefully (`idle_timeout`): an HTTP/1 connection is closed between requests, an HTTP/2 client receives a `GOAWAY` and its open streams are finished first, and a connection that has not finished 5 s later is closed outright. On HTTP/1 this covers the keep-alive wait *and* the time to receive each later request head. A connection with a request in flight is never closed by these timeouts, however slow the upstream or the transfer.
  - A client that **vanishes** (no FIN or RST: a NAT dropped its mapping, a laptop was suspended) is caught by keep-alive instead, request in flight or not. An HTTP/2 client that has sent nothing for `client_idle` is sent a PING, and the connection is closed if the PING is not acknowledged within a quarter of `client_idle`. Every accepted socket also has TCP keepalive enabled, probing a peer silent for `client_idle` (at least 1 s) every quarter of `client_idle` (at least 1 s) and giving it up after 3 unanswered probes, which catches a dead HTTP/1 peer. Either way the connection is closed with reason `client_unresponsive`.

  Timeouts that cannot be served (a `client_idle` so short that a quarter of it is zero) fail the start of the node.
- **Retries (conservative, `retry.rs`).** Only **idempotent** requests without a body (`GET`, `HEAD`, `OPTIONS`, `TRACE`, `DELETE`, and only when the request ends with its head: a chunked or HTTP/2 body counts as a body whatever its headers say) are retried, and only on **connection-establishment / pre-response** failures (including a TLS failure or a reset before any response), at most once (two attempts), against a new backend selection. The node's own connection limit and a timeout are not retried. GFE never retries after any response bytes have been forwarded. This avoids amplifying load during incidents.
- **Limits:** max header bytes (an HTTP/1.1 head over it is answered `431` by the HTTP layer, Section 6.3; on HTTP/2 it is the header list size the node advertises; at least 8192), max concurrent connections (global + per listener), max concurrent h2 streams, and max upstream connections. Exceeding a limit yields a clean `4xx`/`5xx` (or connection refusal) and a counter — never unbounded growth.
- **Synthetic errors (`respond.rs`).** GFE emits compact, consistent error responses (400 request target that is not a path or host error, 404 no-route, 408 stalled upload, 421 misdirected request, 501 protocol upgrade, 502 upstream error, 503 no-healthy-upstream / overloaded, 504 timeout) with a request id, suitable for debugging without leaking internals. To a gRPC caller the same failures are sent as a `grpc-status` (Section 6.7).

---

## 7. Controller Design (Control Plane)

> **Code location:** `gfe/proxy/src/reload/` (controller), `gfe/proxy/src/frontend.rs` + `lib/health-checking/`, `lib/tls/`

The controller runs as Tokio tasks alongside the proxy. It does not handle client requests and shares with the proxy only atomic snapshots (route table, cert store) and the upstream health map.

### 7.1 L7 Health Checking

> **Code location:** `lib/health-checking/`, `gfe/proxy/src/reload/health.rs`

GFE health-checks every upstream in every referenced pool, at **L7**.

Each probe implements the `Probe` trait:

```rust
/// lib/health-checking/src/probe.rs
#[async_trait]
pub trait Probe: Send + Sync {
    async fn check(&self, host: &str, port: u16, timeout: Duration) -> ProbeResult;
}
```

The HTTP and gRPC probes speak through `netkit-http`'s single `Connection`, never through the pooled client the proxy uses: every probe opens a new connection (TCP, and TLS when the probe uses it) and closes it when done, so that a probe also proves the backend still accepts connections. Every probe is bounded as a whole (name resolution, connect, TLS, request and response) by its `timeout`.

| Type | Implementation | Success criterion |
|---|---|---|
| `http`  | `HttpProbe`  | GET a configurable path over HTTP/1.1; the expected status (default 200). Uses TLS for `https` pools and cleartext otherwise, so an `https` pool inheriting the node default (`http`) is probed on its TLS port the way its traffic reaches it. |
| `https` | `HttpProbe`  | Same, always over TLS whatever the pool's scheme. The backend's certificate is not verified: a probe is a liveness signal, not a security boundary, and backends commonly present internal or self-signed certificates. |
| `tcp`   | `TcpProbe`   | TCP connect succeeds. Fallback for non-HTTP upstreams. |
| `grpc`  | `GrpcProbe`  | The gRPC health-checking protocol: `grpc.health.v1.Health/Check` for the server as a whole reports `SERVING`. `NOT_SERVING`, which a gRPC server reports while shutting down, moves the backend to `DRAINING` at once (Section 7.4). Uses TLS for `https` pools and cleartext HTTP/2 otherwise; `path`, `expected_status` and `drain_status` do not apply. |

**Parameters (per pool):**

```toml
interval            = "5s"
timeout             = "2s"
healthy_threshold   = 2
unhealthy_threshold = 3
path                = "/healthz"   # http/https
expected_status     = 200
```

A check, a pool's own or the node's `[health_check_defaults]`, is rejected when its `timeout` is zero, its `interval` is below 100 ms, its `path` does not start with `/`, or its `expected_status` or `drain_status` is outside 100-599.

**Deduplication (`checker.rs`).** A backend appearing in multiple pools is probed once per `(host, port)`, with the check of the first pool it appears in; the result is shared across all referencing pools. A check changed by a reload restarts the probe of every backend it applies to, and so does a change in the pools a backend belongs to; the backend keeps its current status until the new probe's thresholds say otherwise. The health series of a backend under a pool it has left, or of a backend removed altogether, are removed at the reload.

**State machine (`state_machine.rs`):**

```
UNKNOWN   → (healthy_threshold successes)   → HEALTHY
HEALTHY   → (unhealthy_threshold failures)  → UNHEALTHY
UNHEALTHY → (healthy_threshold successes)   → HEALTHY
(any)     → (lame-duck signal)              → DRAINING   (Section 7.4)
```

Health is written to a shared `DashMap<(String, u16), HealthStatus>` keyed by `(host, port)` and read by the data plane on each upstream selection. Because selection consults the live map (not a cached snapshot), a backend going UNHEALTHY stops receiving new requests immediately, with no rebuild step required — the pool simply presents a smaller healthy set on the next selection.

The health checker reaches each upstream directly, at the address its traffic goes to, with no per-network configuration.

### 7.2 Config Manager

> **Code location:** `gfe/proxy/src/reload/`, `gfe/config/`

Responsibilities:

1. **Load** (`gfe/config/src/loader.rs`) the bootstrap node config (TOML) once at startup, and the dynamic config (JSON: listeners, routes, pools, certificates) at startup and on every change.
2. **Validate** (`gfe/config/src/validator.rs`) before applying: at least one listener (an empty config, typically a template that rendered nothing, would close every listening socket and become the last-known-good cache); every route references an existing pool; every listener/route references a loadable certificate (for HTTPS); no duplicate listener binds; host/path patterns well-formed; ports in range; cert and key files parse and match. Invalid config is **rejected wholesale** — the running snapshot is kept.
3. **Apply atomically** (`applier.rs`, driven by `controller.rs`): compile a new `RouteTable` + pools + cert store off the hot path, then swap them via `ArcSwap`. In-flight requests finish on the old snapshot; new requests use the new one. Listener add/remove is reconciled around the swap by the controller (Section 6.1).
4. **Watch** (`watcher.rs`, `lib/tls/src/cert_files.rs`): `notify` (inotify on Linux) on the dynamic config file, with a debounce window that coalesces rapid successive writes (e.g. an editor writing in chunks) into a single reload. The certificate and key files the config names are **polled every 10 s** by `stat` (inode, size, mtime, ctime) rather than watched: their set changes with every reload and they are commonly swapped via rename or symlink, which a poll handles uniformly. A change triggers the same validated reload.
5. **Cache** (`cache.rs`): persist the last-known-good dynamic config locally. A node that starts while the deployed dynamic config is missing, invalid or cannot be applied (e.g. a listener that cannot be bound) starts from the cache instead, so a restart behaves like a rejected reload: what was served before keeps being served. This holds for an in-place upgrade too: a config is validated and built before any listening socket is touched, so an invalid one leaves the sockets inherited from the replaced node to the cache. It reports this as `gfe_config_from_cache = 1` and leaves the cache with the next successful reload. Without a cache, or with an unusable one, the node refuses to start, and its error names both files. The config file's directory is watched before the first config is applied, so a directory that cannot be watched fails the start before any socket is bound. A rejected reload writes no cache.

The file-based model: no central API, no shared runtime state, deployment of the file is the orchestration layer's job (Puppet/Ansible/git), and all nodes converge by being given the same file.

### 7.3 Certificate Manager

> **Code location:** `lib/tls/src/cert_store.rs`, `lib/tls/src/loader.rs`, `lib/tls/src/cert_files.rs`, `gfe/proxy/src/reload/controller.rs`

- On config load and on cert-file change, the manager parses each certificate entry (`loader.rs`), builds an updated cert store, and swaps it in atomically.
- It records each certificate's **not-after** time and exposes `gfe_cert_expiry_timestamp{sni}` so monitoring can alert well before expiry. The series of an SNI that a reload removes is removed with it.
- A certificate that fails to parse or whose key does not match is rejected without disturbing the currently served store; the failure is logged and counted. A rotation caught between the two file writes is therefore harmless: the old certificate keeps being served until the matching key lands, which triggers the next reload.

Certificates are issued and renewed outside GFE: deployment tooling writes the files, and GFE picks them up.

### 7.4 Lame Duck and Graceful Drain

> **Code location:** `lib/health-checking/src/state_machine.rs`, `gfe/proxy/src/frontend.rs`, `lib/listen/src/listeners.rs`, `lib/http/src/server.rs`

**Upstream lame duck (zero-downtime backend deploys).** A backend signals it wants to drain — by serving a configured **lame-duck response** on its health endpoint (`drain_status`, e.g. a `503`), or `NOT_SERVING` to a gRPC probe — and the health state machine moves it to `DRAINING`. While draining:

- The backend is removed from the **new-request** selection set, so it receives no new requests.
- Existing pooled connections and in-flight requests complete normally.
- Idle pooled connections to it are closed after `[upstream] idle_timeout`, as any idle connection is.

This lets teams deploy without resetting live requests.

**GFE node graceful drain (`frontend.rs`, `netkit-listen`, `netkit-http`).** On `SIGTERM`, a GFE node stops following config changes and stops its health checks (backends keep their last status for the rest of the drain), then:

1. Fails its own `/readyz`, so that whatever sends it traffic withdraws it.
2. Stops accepting new client connections.
3. Asks the clients of its open connections to leave, in a way that loses no request:
   - a connection with a request in flight is shut down gracefully at once: the request is answered, an HTTP/2 client is sent a `GOAWAY`, and an HTTP/1 response carries `Connection: close` (every response GFE writes while the node drains ends keep-alive, proxied or its own);
   - a connection with no request in flight is given half the drain deadline to send one more, which is answered the same way. Closing it at once would race with a request the client has already sent. If none comes it is closed (reason `drain`).
4. Exits when no connection is left, or when the drain deadline elapses (`drain_deadline`, default 30s). What is still open then, a long download or a gRPC stream, is cut, and each such connection is counted and logged with reason `shutdown` before the node exits.

A connection accepted in the instant after the drain began is drained the same way.

Because GFE is stateless, draining one GFE node only resets the connections that were live on it; clients reconnect and land on a healthy node.

---

## 8. Configuration Model

Configuration is split into a **bootstrap node config** (TOML, read once at startup) and a **dynamic config** (JSON, watched and hot-reloaded). Both are defined, loaded and validated by `gfe-config` (`gfe/config/`). Unknown keys are rejected in both.

### 8.1 Bootstrap node config (TOML)

```toml
# /etc/gfe/gfe.toml
# Deserialized by gfe/config/src/node.rs (NodeConfig)

[node]
id              = "gfe-node-01"
metrics_addr    = "127.0.0.1:9101"     # /healthz, /readyz, /metrics
worker_threads  = 0                     # 0 = Tokio default (= num CPUs)

[control_plane]
config_file     = "/etc/gfe/gfe-dynamic.json"   # listeners/routes/pools/certs, watched via inotify
local_cache     = "/var/lib/gfe/config-cache.json"
reload_debounce = "250ms"

[tls]
min_version     = "1.2"                 # "1.2" or "1.3"
hsts            = "max-age=31536000; includeSubDomains"
# ticket_key_file = "/etc/gfe/tls-ticket-keys"  # fleet-shared resumption keys (accepted, not used yet)

[limits]
max_connections          = 100000       # global concurrent client connections
max_connections_listener = 50000        # per listener
max_header_bytes         = 65536
max_h2_concurrent_streams = 256
max_upstream_connections = 20000        # global, across all pools
                                        # every limit must be > 0: 0 is not "unlimited"

[timeouts]                              # every timeout must be > 0s
tls_handshake     = "10s"
request_header    = "10s"
upstream_connect  = "3s"
upstream_first_byte = "30s"
request_total     = "60s"
client_idle       = "75s"
drain_deadline    = "30s"

[upstream]
idle_per_host     = 32                  # idle pooled connections kept per backend (unset or 0: 32)
idle_timeout      = "60s"               # close a pooled upstream connection idle for this long
# client_cert_file = "/etc/gfe/upstream-client.pem"   # mTLS to https backends
# client_key_file  = "/etc/gfe/upstream-client.key"
# extra_ca_file    = "/etc/gfe/upstream-ca.pem"       # trusted besides the system's CAs

[log]
file              = "/var/log/gfe/gfe.log"   # absent: everything to standard output

[health_check_defaults]
interval             = "5s"
timeout              = "2s"
healthy_threshold    = 2
unhealthy_threshold  = 3
path                 = "/healthz"
```

**Deprecated keys.** Two keys are still accepted, so that an existing file keeps loading, but ignored. The node logs a warning for each one the file sets when it starts, saying what to do about it:

| Key | Why it went |
|---|---|
| `[node] loopback_vip` | Nothing in GFE assumes how traffic reaches a node; listeners bind the addresses of the dynamic config. Remove it. |
| `[ebpf]` (and its `enabled`) | The kernel view is part of every node (Section 11.1): every node attempts to attach it, whatever the section says. Remove the section. |

### 8.2 Dynamic config (JSON, hot-reloaded)

```json
{
  "certificates": [
    {
      "sni": ["api.example.org", "*.api.example.org"],
      "cert_file": "/etc/gfe/certs/api.example.org.fullchain.pem",
      "key_file":  "/etc/gfe/certs/api.example.org.key.pem"
    },
    {
      "default": true,
      "cert_file": "/etc/gfe/certs/default.fullchain.pem",
      "key_file":  "/etc/gfe/certs/default.key.pem"
    }
  ],
  "listeners": [
    { "id": "https", "address": "188.184.100.10", "port": 443, "protocol": "https" },
    { "id": "http",  "address": "188.184.100.10", "port": 80,  "protocol": "http"  }
  ],
  "routes": [
    {
      "id": "atlas-web",
      "listener": "https",
      "host": "atlas.example.org",
      "path_prefix": "/",
      "action": { "forward": "atlas-web-pool" }
    },
    {
      "id": "http-to-https",
      "listener": "http",
      "host": "*",
      "path_prefix": "/",
      "action": { "redirect": { "scheme": "https", "status": 308 } }
    }
  ],
  "pools": [
    {
      "id": "atlas-web-pool",
      "scheme": "https",
      "lb_policy": "round_robin",
      "upstreams": [
        { "host": "188.185.10.1", "port": 8443, "weight": 1 },
        { "host": "188.185.10.2", "port": 8443, "weight": 1 },
        { "host": "10.254.0.5",   "port": 8443, "weight": 1 }
      ],
      "health_check": {
        "type": "https",
        "path": "/healthz",
        "interval": "5s",
        "timeout": "2s",
        "healthy_threshold": 2,
        "unhealthy_threshold": 3
      }
    }
  ]
}
```

> **Why JSON for the dynamic part and TOML for the bootstrap part?** The bootstrap config is small, hand-edited, and node-specific (TOML reads well by hand); the dynamic config is fleet-wide, machine-generated by deployment tooling, and reloaded constantly (JSON is the universal generation target). Keeping them separate also means a bad dynamic reload never touches the node's identity/bind settings.

---

## 9. TLS Policy

A single, centrally enforced policy applies to every HTTPS listener:

- **Minimum protocol version:** TLS 1.2 (default) or TLS 1.3-only (configurable). SSLv3/TLS 1.0/1.1 are never offered.
- **Cipher suites / signature schemes:** rustls's defaults with the `ring` provider: AEAD only, forward secrecy required.
- **ALPN:** advertises `h2` then `http/1.1`.
- **HSTS:** added to the responses relayed from backends over HTTPS, per `[tls].hsts` (empty, the default: none).
- **Session resumption:** TLS 1.3 PSK / TLS 1.2 tickets from a per-node ticketer (Section 6.2).
- **SNI:** connections without SNI, or whose SNI matches no certificate, are served the default certificate, or fail the handshake if no default is configured.
- **mTLS from clients:** not supported (the public edge does not require client certs); the upstream leg may use mTLS (Section 6.6).

Centralizing this is the point: teams get correct, uniform, audited TLS with zero per-team configuration.

---

## 10. Upstream Requirements

Application backends behind GFE are ordinary HTTP servers, reached over an ordinary client connection from the GFE node's address to the backend's. Requirements are minimal:

- **Reachability:** the backend's address is routable from GFE nodes.
- **A health endpoint:** an HTTP(S) path returning the expected status when ready (default `/healthz`, 200), or the gRPC health service. To use lame-duck draining, it returns the configured drain signal when the backend wants to stop receiving new requests.
- **Real client IP awareness:** backends read the original client IP from `X-Forwarded-For` / `Forwarded` rather than the socket peer (which is the GFE node).
- **(Optional) Upstream TLS:** if `scheme=https`, the backend presents a certificate GFE can validate (the system's trust store, or `extra_ca_file`) for the name it is configured under; for mTLS, it requires GFE's client certificate.

---

## 11. Observability

> **Code location:** `gfe/proxy/src/metrics/` (every metric), `lib/observability/` (the registry's exposition and the log), `gfe/proxy/src/edge/conn_record.rs` and `gfe/proxy/src/handler/record.rs` (what is recorded), `gfe/proxy/src/kernel.rs` (the kernel view)

### 11.1 Metrics

Each GFE node exposes Prometheus metrics at `http://<node>:9101/metrics`. With `?histograms=untyped` the histograms are exposed without their `# HELP` and `# TYPE` lines, for collectors that lose a histogram they are told is one (see the [observability guide](observability.md#collectors-that-lose-histograms)); any other value is refused with `400`.

**Proxy / data-plane metrics (`metrics/proxy.rs`):**

| Metric | Type | Description |
|---|---|---|
| `gfe_connections_accepted_total` | Counter | Client connections accepted (labels: listener) |
| `gfe_connections_active` | Gauge | Currently open client connections |
| `gfe_listener_connections_active` | Gauge | Currently open client connections (label: listener) |
| `gfe_connections_rejected_total` | Counter | Connections rejected (label: reason ∈ {limit, handshake_timeout}) |
| `gfe_connections_closed_total` | Counter | Closed connections (labels: listener, reason ∈ {closed, client_abort, client_unresponsive, idle_timeout, header_timeout, drain, protocol_error, tls_handshake_failed, tls_handshake_timeout, error, shutdown}; see below) |
| `gfe_connection_duration_seconds` | Histogram | Lifetime of client connections (label: listener) |
| `gfe_bytes_in_total` / `gfe_bytes_out_total` | Counter | Bytes read from / written to client sockets, on the wire (TLS included), counted as they flow (label: listener) |
| `gfe_tls_handshakes_total` | Counter | TLS handshakes (label: result ∈ {ok, failed}) |
| `gfe_tls_handshake_failures_total` | Counter | Failed handshakes (label: reason ∈ {invalid_message, peer_incompatible, alert_received, peer_misbehaved, client_closed, io_error, other}) |
| `gfe_tls_connections_total` | Counter | TLS connections established (labels: version, cipher, alpn, resumed) |
| `gfe_tls_handshake_duration_seconds` | Histogram | Handshake latency |
| `gfe_tls_sni_no_cert_total` | Counter | Handshakes with no matching certificate |
| `gfe_requests_total` | Counter | Finished requests (labels: listener, vhost, route, status). `vhost` is the matched route's configured host pattern, never the raw `Host`; it is not called `host`, which monitoring systems commonly use for the machine a series comes from. Both are `none` for a request that matched no route. Status `499` = abandoned by the client before GFE had a response |
| `gfe_requests_in_flight` | Gauge | Requests received whose response is not finished yet |
| `gfe_requests_aborted_total` | Counter | Requests broken off before completion (labels: listener, vhost, route, by ∈ {client, upstream}) |
| `gfe_request_duration_seconds` | Histogram | Time from the request head to the last byte of the response (labels: listener, vhost, route) |
| `gfe_request_body_bytes_total` / `gfe_response_body_bytes_total` | Counter | Body bytes received from / sent to clients (labels: listener, vhost, route) |
| `gfe_grpc_responses_total` | Counter | Finished gRPC calls (labels: listener, vhost, route, grpc_status = the numeric gRPC status code, 0 is OK) |
| `gfe_no_route_total` | Counter | Requests matching no route (404) |
| `gfe_no_healthy_upstream_total` | Counter | Requests with no healthy upstream (503) |
| `gfe_upstream_requests_total` | Counter | Upstream requests (labels: pool, backend, status) |
| `gfe_upstream_request_duration_seconds` | Histogram | Upstream round-trip latency, to the response headers (labels: pool, backend) |
| `gfe_upstream_errors_total` | Counter | Upstream requests that failed before any response (labels: pool, backend, kind ∈ {connect_timeout, connect_refused, connect_error, tls, reset, connection_limit, timeout, other}) |
| `gfe_upstream_connect_errors_total` | Counter | The same, all kinds together (kept for existing dashboards) |
| `gfe_upstream_retries_total` | Counter | Requests retried against a new backend selection (label: pool) |
| `gfe_upstream_pool_full_total` | Counter | Requests answered `503` because their pool had `max_in_flight` requests in flight (label: pool) |
| `gfe_upstream_requests_in_flight` | Gauge | Requests a backend is working on, until the response has been relayed to its end (labels: pool, backend) |
| `gfe_upstream_connections` / `gfe_upstream_connections_limit` | Gauge | Upstream connections open or being opened over all backends, sampled at scrape time, and the configured `max_upstream_connections` |

**Why a connection closed.** The `reason` is how the connection ended as `netkit-http`'s server reports it, or what its TLS handshake did before that; `close_reason` in `conn_record.rs` maps one to the other.

| reason | when |
|---|---|
| `tls_handshake_failed` | the TLS handshake failed |
| `tls_handshake_timeout` | the TLS handshake did not finish within `tls_handshake` |
| `header_timeout` | the first request head was not complete within `request_header` |
| `idle_timeout` | no request in flight for `client_idle`: an HTTP/1 connection closed between requests, an HTTP/2 client sent a `GOAWAY` (and closed outright if it had not left 5 s later); or an HTTP/1.1 client that took longer than `client_idle` to send a request head after the first; or an HTTP/2 connection that never carried a request and did not answer a PING |
| `drain` | the node drains, the client was asked to leave, and it did |
| `client_abort` | the client reset the connection, or went away in the middle of a message, a request head included |
| `client_unresponsive` | an HTTP/2 client that carried requests did not acknowledge a PING within a quarter of `client_idle`, or the kernel gave the client up (TCP keepalive, retransmissions) |
| `protocol_error` | the client sent what is not HTTP, or a head over `max_header_bytes` (an HTTP/1.1 client is answered `400` or `431` first) |
| `closed` | the client closed the connection, or it ended in an orderly way |
| `shutdown` | the connection was still open at the drain deadline and was cut |
| `error` | anything else, the `error` field of `gfe::conn` saying what; also a connection whose task panicked |

**Control-plane metrics (`metrics/control.rs`):**

| Metric | Type | Description |
|---|---|---|
| `gfe_backend_health_status` | Gauge | 1=HEALTHY, 0=UNHEALTHY (labels: pool, backend); DRAINING exposed separately |
| `gfe_backend_draining` | Gauge | 1 if backend is in lame-duck DRAINING (labels: pool, backend) |
| `gfe_health_check_duration_seconds` | Histogram | Probe round-trip time |
| `gfe_config_last_reload_timestamp` | Gauge | Unix time of last successful dynamic-config reload |
| `gfe_config_reload_errors_total` | Counter | Failed reloads (kept old snapshot) |
| `gfe_config_reload_failed` | Gauge | 1 while the last attempt to load the dynamic config failed (a rejected reload, or a start from the cache), 0 once one succeeds; what `GfeConfigReloadFailing` alerts on |
| `gfe_config_from_cache` | Gauge | 1 while the node serves its last-known-good cache because the deployed dynamic config was unusable at startup |
| `gfe_upgrade_failures_total` | Counter | In-place upgrades that failed: the successor did not take over and the node went on serving as it was |
| `gfe_cert_expiry_timestamp` | Gauge | not-after Unix time (label: sni) — alert before expiry |
| `gfe_active_routes` / `gfe_active_pools` | Gauge | Sizes of the current snapshot |

**Saturation (`metrics/process.rs`, `metrics/proxy.rs`):**

| Metric | Type | Description |
|---|---|---|
| `gfe_connections_limit` / `gfe_listener_connections_limit` | Gauge | The configured `max_connections` / `max_connections_listener`, so connection saturation is `gfe_connections_active / gfe_connections_limit` |
| `process_open_fds` / `process_max_fds` | Gauge | Open file descriptors and their limit (Linux). Running out of descriptors is how a proxy usually fails first |
| `process_resident_memory_bytes` | Gauge | Resident memory (Linux) |
| `process_cpu_seconds_total` | Counter | User + system CPU time (Linux); `rate()` of it is cores in use |
| `process_start_time_seconds` | Gauge | Process start, Unix seconds (restarts show as a step) |
| `gfe_runtime_workers` / `gfe_runtime_alive_tasks` / `gfe_runtime_global_queue_depth` | Gauge | Async runtime: worker threads, live tasks, and tasks queued for a free worker — the last one rising means the workers are saturated |
| `gfe_log_lost_lines` | Gauge | Log lines that were never written, since the node started (label: destination). The destination was too slow and the queue was full, or it refused them |
| `gfe_build_info` | Gauge | Always 1 (label: version) |

The `process_*` names are the ones every Prometheus client library uses, so stock dashboards and alerts apply unchanged.

**Kernel view (`netkit-kernel`, `metrics/kernel.rs`; `gfe_accept_queue_wait_seconds` in `metrics/proxy.rs`) — part of every node:**

Some facts about a connection exist only in the kernel. Every node attempts to attach a small eBPF program that reports them; a node that cannot serves without it, and says so (below).

| Metric | Type | Description |
|---|---|---|
| `gfe_ebpf_attached` | Gauge | 1 while the kernel program is attached, 0 otherwise. At 0 the node runs without its kernel view (alert `GfeKernelViewNotAttached`) |
| `gfe_ebpf_lost_events` | Gauge | Closed connections the kernel could not report because the reader fell behind |
| `gfe_accept_queue_wait_seconds` | Histogram | Time a connection spent established but not yet accepted (label: listener). The earliest sign of a node falling behind |
| `gfe_client_tcp_rtt_seconds` | Histogram | Smoothed round-trip time to the client when its connection closed (label: listener) |
| `gfe_client_tcp_segments_sent_total` / `gfe_client_tcp_retransmits_total` | Counter | Segments sent / retransmitted to clients on closed connections (label: listener); their ratio is the loss clients experience |
| `gfe_client_tcp_closes_total` | Counter | Closed client connections (labels: listener, ending ∈ {peer_closed, node_closed, aborted, other}) |
| `gfe_upstream_tcp_rtt_seconds` | Histogram | The same for connections to backends (label: backend = `ip:port` as the kernel sees it): network distance to a backend, separate from how fast it answers |
| `gfe_upstream_tcp_segments_sent_total` / `gfe_upstream_tcp_retransmits_total` | Counter | (label: backend) |
| `gfe_upstream_tcp_closes_total` | Counter | (labels: backend, ending) |

How it works, and what it does not assume:

- One `sockops` program (`lib/kernel/bpf/tcp_events.bpf.c`) is attached to the **cgroup the node runs in**, so it sees exactly the node's sockets: connections it accepts and connections it opens (traffic to backends and health probes alike). It observes **sockets, not packets**, and is therefore indifferent to how traffic reached the node.
- `ending` is read from the TCP state a connection was closed from: who sent its FIN first (`peer_closed`, `node_closed`), or no orderly shutdown at all (`aborted`: a reset in either direction, or the kernel giving up on a silent peer). On TLS connections the node usually closes first, in answer to the client's `close_notify`.
- Statistics are reported once per connection, when it closes. A long-lived connection contributes when it ends.
- Requirements: Linux ≥ 5.8 with cgroup v2, and `CAP_BPF` + `CAP_NET_ADMIN`, which the shipped systemd unit grants. A Linux build always contains the program: building it needs clang, and a Linux build without clang fails rather than producing a node that can never see its connections. The kernel program is C, checked by the kernel's verifier before it runs; the Rust side has no `unsafe`. A node that cannot attach the program (a missing capability, an old kernel, not Linux) logs the reason at error level, sets `gfe_ebpf_attached` to 0, and serves without the kernel view: observability failing must not become an availability failure.

**What else could move to the kernel.** The node's owner wants to offload to eBPF whatever improves performance. None of the following is implemented; they are candidates, each with what it would save and what it would cost:

- *Refusing connections over the limit before `accept`.* Today a connection over `max_connections` is accepted and closed at once, which costs a system call pair and a descriptor per refused connection. A cgroup or XDP program dropping SYNs while a listener is saturated would save that, at the cost of the program knowing the node's live count (a map the node writes) and of clients seeing a timeout instead of a reset.
- *Setting socket options from the `sockops` program.* `TCP_NODELAY` and keepalive are set by two system calls per accepted connection. The `sockops` program already sees every connection and could set them, saving those calls, at the cost of the values living in a map the node fills and of the options no longer being set where the kernel view is not attached.
- *Steering new connections across accept queues.* `SO_REUSEPORT` with one socket per worker and an eBPF program choosing the socket would spread accepts evenly and remove contention on one queue, at the cost of more sockets per listener, which the reload reconciliation and the upgrade handover would have to carry.
- *Kernel TLS.* Not eBPF, but the offload that would matter most for an upload-heavy workload: after the handshake, the kernel would encrypt and decrypt, and bodies could move without a copy through user space. It needs `unsafe` or a crate that wraps it, and `netkit-tls` would have to hand the socket to the kernel after the handshake.

TLS termination and HTTP parsing, which are where the CPU goes, cannot be offloaded to eBPF.

### 11.2 Logging

- **Structured JSON logs** via `tracing` + `tracing-subscriber`.
- **Access logs** (`gfe/proxy/src/handler/record.rs`): one structured event per request under the target `gfe::access`, emitted when the exchange is **over** — the response written to its last byte, or abandoned — so sizes, duration and outcome are final. A request the client gives up on before any response is still logged. Every request that reaches GFE's request handler is reported exactly once, whatever happens to it; the requests the HTTP layer answers itself (Section 6.3) are not. Fields:

  | Field | Meaning |
  |---|---|
  | `request_id` | Client-supplied `X-Request-Id` if valid, else generated; also sent upstream and returned on responses |
  | `client`, `client_port` | Peer address of the connection |
  | `listener`, `proto`, `http_version`, `sni` | Where and how the request arrived |
  | `method`, `host`, `path`, `user_agent` | The request (no query string, no other headers) |
  | `status` | Response status; `499` when the client left before a response existed |
  | `grpc_status` | For gRPC calls (`content-type: application/grpc*`), the numeric status the call ended with, read from the response trailers (or headers, for calls that fail before any message). A gRPC call is HTTP `200` whatever its outcome, so this is the field that tells success from failure |
  | `route`, `pool`, `backend`, `attempts` | Routing decision, the backend of the last attempt, and how many attempts were made |
  | `error` | Why GFE answered itself: `no_route`, `pool_not_found`, `no_healthy_upstream`, `upstream_connect_timeout`, `upstream_connect_refused`, `upstream_connect_error`, `upstream_tls`, `upstream_reset`, `upstream_connection_limit`, `upstream_pool_full` (a `503`: the pool has `max_in_flight` requests in flight), `upstream_error`, `upstream_timeout`, `request_body_timeout` (a `408`: the client stalled while sending the body), `unsupported_request_target` (a `400`: the target of a forwarded request is not a path, as in `OPTIONS *` or `CONNECT`), `upgrade_not_supported` (a `501`: the request asked for a protocol upgrade, such as WebSocket), `host_conflict` / `host_missing` (a `400`), `misdirected_request` (a `421`; see Section 6.3) |
  | `termination` | `complete`, `client_abort` (client left before or during the response) or `upstream_abort` (upstream failed mid-body) |
  | `request_bytes`, `response_bytes` | Body bytes actually read from / written to the client |
  | `duration_ms` | Request head to last response byte, microsecond resolution |
  | `upstream_ttfb_ms` | First upstream attempt to upstream response headers |
  | `tls_version`, `tls_cipher` | Negotiated TLS parameters of the connection the request arrived on |

  Fields that do not apply to a request are omitted.
- **Connection logs** (`gfe/proxy/src/edge/conn_record.rs`): one structured event per client connection under the target `gfe::conn`, emitted when the connection is gone. Fields: `client`, `client_port`, `listener`, `proto`, `sni`, `tls_version`, `tls_cipher`, `alpn`, `tls_resumed`, `tls_handshake_ms`, `tls_error` (why a handshake failed), `accept_wait_ms` (time in the accept queue; only while the kernel view is attached), `requests` (started on the connection), `bytes_in` / `bytes_out` (on the wire), `duration_ms`, `reason` (as in `gfe_connections_closed_total`) and `error` (the error the connection ended with, as the HTTP layer or the TLS handshake reported it, when there was one). Both targets can be silenced or routed independently, e.g. `RUST_LOG=info,gfe::conn=off`.
- **TCP logs** (`gfe/proxy/src/kernel.rs`, while the kernel view is attached): one event per closed TCP connection under the target `gfe::tcp`. Fields: `side` (`client` or `upstream`), `client` and `client_port` (the same as in the `gfe::conn` event of that connection) or `backend`, `listener`, `ending`, `rtt_ms`, `min_rtt_ms`, `retransmits`, `segments_sent`, `bytes_acked`, `bytes_received`, `lifetime_ms`.
- **The node's own log**: every other line, at `info` and above by default, with the module it comes from as its target (`gfe_proxy::...`, `gfe_node::...`, `netkit_...::...`). No target is muted by default: the libraries log nothing at `info` or above about healthy traffic or about a client that misbehaves, which the `gfe::conn` and `gfe::access` events already describe. Why a request to a backend failed is at debug level under `gfe::proxy` (Section 6).
- **Where the log goes** (`[log]` in the bootstrap config). By default every line goes to standard output, which under systemd is the journal. With `[log] file = "/var/log/gfe/gfe.log"` every line is appended to that file, and standard output keeps the node's own log only: the access, connection and TCP events go to the file alone. A journal is the wrong place for one line per request, and journald silently discards what exceeds its rate limit (10,000 lines per 30 s per service by default). The node does not rotate the file. It may be renamed, removed or truncated under the node, which goes on at the configured path within a second; a file that cannot be opened there fails every line, and counts it as lost, until it can. The file is created with mode `0640`.
- **Writing the log never holds up a request** (`lib/observability/src/logging.rs`). An event is formatted where it happens and queued; a thread of its own writes the queue out. A destination slower than the node logs fills the queue (128,000 lines), and from then on lines are dropped rather than waited for. Lines dropped, or refused by the destination, are counted in `gfe_log_lost_lines`. What is still queued when the node exits is written out first.
- Log levels: set by `RUST_LOG` when the node starts (default `info`, which the unit sets). There is no change at runtime: a new level needs a new process started with it.
- **No body logging.** Headers are logged selectively (allowlist) to avoid leaking secrets.

### 11.3 Health Endpoints

Served on the metrics address:

```
GET /healthz   → 200 if the proxy is running
GET /readyz    → 200 if at least one listener is bound and a valid config is loaded;
                 503 while draining — this is what whatever sends traffic to the node should probe
GET /metrics   → Prometheus exposition (?histograms=untyped: histograms as plain series)
```

The ops server (`gfe/node/src/ops.rs`) serves at most 64 connections at once and closes any over that at once, so it cannot use up the descriptors the proxy needs. A client has 5 s to send a request head, and a connection it keeps is closed after 5 s without one. It speaks HTTP/1.1, and HTTP/2 with prior knowledge (at most 4 streams on a connection), and answers pipelined requests. Every method is answered as `GET` is; any other path gets a `404`. `/metrics` samples the runtime gauges, `gfe_upstream_connections`, `gfe_log_lost_lines` and `gfe_ebpf_lost_events` at scrape time. Once the ops socket has been handed to a successor (Section 13), the connections still open to the node are drained, so that the next probe or scrape reaches the successor.

When the node starts it logs one warning for each deprecated key its bootstrap config sets (Section 8.1), right after the log is started.

---

## 12. Failure Modes and Resilience

### GFE Node Failure

- Whatever spreads traffic over the fleet detects the failed node through its probe of `/readyz` and stops sending it new connections. Remaining GFE nodes absorb the traffic, with no coordination.
- **Connection impact:** connections that were live on the failed node reset; clients reconnect and land on a healthy node. GFE statelessness makes any node a valid replacement.
- **Capacity:** size the GFE fleet with N+1 headroom so any N−1 nodes carry full load.

### Upstream Failure

- The L7 health checker detects it within `interval × unhealthy_threshold` (default 15s) and removes it from the pool's healthy set; no new request is sent to it.
- In-flight requests to a backend that fails mid-response cannot be safely retried (bytes already sent) and end with `termination=upstream_abort`; pre-response failures on idempotent bodyless requests are retried once against another selection (Section 6.8).
- If a pool has no healthy upstreams, requests get 503; the route still exists, so recovery is automatic when a backend returns.

### Config / Cert Source Unreachable

- The dynamic config and certs are local files; GFE never makes a runtime call to fetch them. If the deployment tooling cannot push an update, GFE keeps serving the last-loaded (and locally cached) config indefinitely.
- A malformed reload is rejected wholesale; the running snapshot is retained, `gfe_config_reload_errors_total` increments and `gfe_config_reload_failed` stays 1 until a reload succeeds.
- A node restarted while its dynamic config is missing or broken starts from the last-known-good cache (Section 7.2) and sets `gfe_config_from_cache`.

### Certificate Expiry

- `gfe_cert_expiry_timestamp{sni}` drives proactive alerting; renewal and rotation are the job of the deployment tooling. An expired cert is still served (so the failure mode is a visible TLS warning, not a hard outage) but alerts fire well before.

### Kernel View Unavailable

- A node that cannot attach its eBPF program serves exactly as it would with it; only the kernel metrics, `accept_wait_ms` and the `gfe::tcp` events are missing. `gfe_ebpf_attached` is 0 and `GfeKernelViewNotAttached` fires; the node's log says why at startup.

### Overload

- Connection and stream limits bound resource use; excess connections are refused cleanly rather than driving the node into memory pressure. Upstream connection caps protect backends from connection storms during failover.
- The proxy applies backpressure naturally: slow clients or upstreams throttle their own streams without starving others (per-connection, async).

### Reload Under Load

- Route table and cert store swaps are atomic `ArcSwap` pointer updates; in-flight requests complete on the old snapshot. There is no stop-the-world, no dropped connections, and no lock contention on the hot path.

---

## 13. Operational Considerations

### Upgrading a Node in Place

> **Code location:** `gfe/node/src/upgrade.rs`, `gfe/node/src/handover.rs`, `lib/listen/src/handover.rs`

A new binary, or a change to the bootstrap config (which is read once, at startup), needs a new process. It does not need the listening sockets to be closed. On `SIGUSR2` a node replaces itself (Unix only):

1. It starts the binary it was started from, as that binary is on disk now, with the same arguments and `--upgrade`. What it starts only starts the successor proper and exits, so the successor is not the node's child and is adopted by the service manager at once.
2. It gives that successor its listening sockets, the proxy's and the ops server's, over a Unix socket (`SCM_RIGHTS`). Both processes now hold the same sockets, and each socket has a single queue of waiting connections, which either process accepts from.
3. The successor loads its config as any node does, listens on the sockets it was given instead of binding, and tells the node once it accepts connections. It answers on the ops socket only from then on, so a probe of `/readyz` never finds it not ready yet.
4. Only then does the node stop accepting, leave the ops endpoints to the successor, and drain as on `SIGTERM` (Section 7.4): requests in flight are answered, clients are asked to reconnect, and they reach the successor when they do. Connections kept open to the ops endpoints are closed once their request in flight is answered, so the next probe or scrape reaches the successor; a probe that still reaches the node is answered as ready, since the successor serves the address.

No connection is refused, because the sockets are never closed, and none waiting to be accepted is lost, because the queue it waits in outlives the node. What an upgrade can still cut is what a drain cuts: a request or stream still running when the drain deadline elapses.

Under systemd this is `systemctl reload gfe-node`. The unit is of `Type=notify`: the node tells systemd when it serves and, once its successor has taken over, that the successor is the service's main process, so the node's own exit is not taken for the service stopping. By then the successor is systemd's own child, which matters: systemd does not wait for a main process that is some other process's child, and kills it outright when the service is next stopped.

If the successor does not take over (the binary does not start, the config is rejected, it does not answer within 60 s), nothing has changed for the node: it goes on serving, logs why, and counts the attempt in `gfe_upgrade_failures_total`. This makes a bootstrap config change as safe to roll out as a dynamic one. The 60 s count from when the successor is started, for the whole exchange. A node told to stop (`SIGTERM`, `systemctl stop`) while it waits for its successor does not wait any longer: it abandons the upgrade, stops the successor if it has said which process it is (one that has not finds nobody to take over from and exits), and drains as on any stop.

What does not carry over: the successor starts with empty connection pools to the backends, every backend presumed healthy until probed, and its counters at zero.

While a node is upgraded in place, the outgoing process and its successor are in the same cgroup and each has its own kernel program attached. The outgoing one stops reporting the moment its successor takes over, so nothing is reported twice.

What an upgrade in place does not do:

- **Apply a change to the unit.** The successor is started by the running node, not by systemd, so it runs with the capabilities, limits, environment and sandbox the service was started with. A changed unit needs `systemctl restart`.
- **Tell the caller how it went.** `systemctl reload` returns once the node has been signalled. The outcome is in `systemctl status` (`Serving (upgraded in place)`, or `Upgrade failed, still serving: ...`), in the journal, and in `gfe_upgrade_failures_total`, which the shipped rules alert on.
- **Work from a version that does not know `SIGUSR2`.** Such a node is killed by the signal. The first update to a version with this feature is a restart.
- **Make sense in a container.** There the node is the container's first process and the container ends with it: replace the container instead.

### Rolling Restarts

Where a node cannot be upgraded in place, it is restarted:

1. Drain the node (`SIGTERM`): `/readyz` flips to 503, and whatever sends the node traffic withdraws it within its probe window.
2. The node stops accepting new connections, asks its clients to leave, and serves in-flight requests until they finish or the drain deadline elapses.
3. Restart the `gfe-node` binary; it loads config (or cache), binds listeners, passes `/readyz`, and receives traffic again.

Between the first and the last step the node's sockets are closed: a client that reaches the node without going through whatever probes `/readyz` is refused.

Statelessness means a restarted node is immediately a full peer — no warmup state to rebuild beyond connection pools, which refill on demand.

### Adding a GFE Node

1. Provision the node, install the package and the config files.
2. Start the service; once it passes `/readyz`, add it to whatever spreads traffic over the fleet.
3. Capacity increases immediately; existing connections on other nodes are unaffected.

### Adding / Changing a Route, Pool, or Certificate

1. Deployment tooling writes the updated dynamic-config JSON (and any cert files) to each GFE node. It should gate the write on `gfe-node --check-config --dynamic-config <candidate>`, which runs on the candidate file everything a reload runs short of swapping it in (validation, certificate loading, route compilation, pool building) before it replaces the deployed one (e.g. as a Puppet `validate_cmd`); adding `--config <toml>` checks the bootstrap config in the same run.
2. The inotify watcher fires; the config manager validates and atomically swaps the snapshot within the debounce window.
3. New requests use the new routing/certs immediately; in-flight requests finish on the old snapshot. No restart, no dropped connections.

### Rotating Certificates

- Write the new cert/key files in place (and update the dynamic config if the path/SNI set changed). The certificate poller notices within 10 s, reloads, and swaps the cert store atomically — no config change or restart needed.

### Capacity Planning

- The dominant costs at the GFE tier are **TLS handshakes/sec** (CPU) and **concurrent connections** (memory + FDs), not raw bandwidth. Size for handshake rate and connection count; connection pooling keeps upstream connection counts far below client connection counts.

---

## 14. What Is Not There

What a node does not do, so that nobody has to find out the hard way:

- **Fleet-shared TLS ticket keys.** `[tls] ticket_key_file` is accepted and not used. Resumption works on the node that issued the ticket; a resumed session that lands on another node makes a full handshake.
- **WebSocket and other protocol upgrades** are refused with `501` (Section 6.7).
- **HTTP/3 (QUIC)** downstream.
- **Rate limiting** beyond the connection, stream and quota limits of Section 6.8.
- **Certificate issuance or renewal.** Certificates are files that deployment tooling writes.
- **An access event for what the HTTP layer answers itself**: a malformed head (`400`), a head over `max_header_bytes` (`431`) (Section 6.3). The connection log records them.
- **Closing a backend's idle connections when it turns unhealthy or drains.** They are closed after `[upstream] idle_timeout`.
- **Response caching, and request/response header transformation rules.**

---

## 15. Differences from v1.1.0

`v1.1.0` is the released version. This one keeps its flags, signals, both config schemas, metric names and labels, the targets and fields of the access and connection events, and the handover protocol: a `v1.1.0` node upgrades in place to this one (`systemctl reload gfe-node`). What an operator upgrading a fleet will notice:

Configuration and start:

- `[node] loopback_vip` and `[ebpf]` are accepted, ignored, and warned about at startup (Section 8.1): GFE assumes nothing about what is in front of it, and the kernel view is part of every node. The startup log line has no `vip` field.
- ACME `http-01` is gone, and with it the `unknown_acme_challenge` error.
- The kernel view is always attempted and never fatal. `gfe_ebpf_enabled` is gone, and `GfeKernelViewNotAttached` fires on `gfe_ebpf_attached == 0`. A node that cannot attach it logs why at error level. The systemd unit grants `CAP_BPF` and `CAP_NET_ADMIN` itself, and the `gfe-node-ebpf.conf` drop-in is no longer shipped; a drop-in installed from it must be removed (see the [RPM guide](rpm.md)).
- A config directory that cannot be watched fails the start before any socket is bound.
- Client timeouts that cannot be served (a `client_idle` so small that a quarter of it is zero) fail the start, instead of every connection.

Clients:

- Client addresses in logs are canonical: `192.0.2.1`, not `::ffff:192.0.2.1`.
- `X-Request-Id` is added to proxied responses that do not carry one.
- An idle HTTP/2 connection is closed at `client_idle` even when `request_header` is longer; `v1.1.0` waited until `request_header` had passed.
- A connection accepted after a drain began is drained too; one shut down before it sent a byte is reported as `drain`, not `error`.
- A request head that arrived in time is served even when the node, short of CPU, looks at it after `request_header` has passed; `v1.1.0` could close such a connection as `header_timeout`.
- A client that leaves in the middle of an upload is a `499` (`client_abort`) with the bytes sent so far, and counts nothing against the backend; `v1.1.0` could count an upstream error.

Backends:

- Upstream TLS is verified against the system's trust store (plus `extra_ca_file`), not against roots compiled into the binary. A store that cannot be read is a warning at startup, not a failure.
- `upstream_connect` bounds the name lookup, the TCP connect and the TLS handshake together; it bounded the TCP connect alone.
- The address of a named backend is cached for 10 s, and the last answer is kept when a lookup fails.

Connections and draining:

- Connections still open at the drain deadline are cut and reported with close reason `shutdown` before the node exits.
- `gfe_tls_sni_no_cert_total` is fed.

The log:

- Lines whose target is a module path start with `gfe_proxy`, `gfe_node` or `netkit_` (they started with `gfe_core`, `gfe_proxy`, ...): `RUST_LOG` directives that name modules need the new names. The targets of the access and connection events (`gfe::access`, `gfe::conn`) and their fields are unchanged.

Building:

- Rust 1.88 or later (edition 2024); clang on Linux, for the eBPF program.

Throughput is the same within the noise of the measurement: `hack/loadtest.sh 64 6`, on one laptop (loopback; the load client and the mock backend share its cores), `v1.1.0` measured on the same machine:

| scenario | v1.1.0 | this version |
|---|---|---|
| http, fixed response, kept connections | 150,487 req/s | 149,577 req/s |
| http, proxied, kept connections | 68,940 req/s | 68,042 req/s |
| https, proxied, kept connections | 66,967 req/s | 67,856 req/s |
| https, proxied, a new TLS connection per request (8 clients) | 10,337 req/s | 11,452 req/s |

---

## 16. Technology Stack

Each third-party crate is named, in the `[dependencies]` of a manifest, by the crates in the third column only; the others reach it through them.

| Component | Technology | Crate(s) | Rationale |
|---|---|---|---|
| Language | Rust (1.88 or later, edition 2024) | all | Memory safety without GC pauses; strong async ecosystem |
| Async runtime | `tokio` | all | The natural model for an L7 proxy |
| HTTP/1.1 and HTTP/2 | `hyper` + `hyper-util` (with `h2`); `http`, `http-body`, `http-body-util`, `bytes`, `tower-service` | `netkit-http` | Both protocols, serving and requesting, and a connection pool; the `http` vocabulary is re-exported as it is |
| TLS | `rustls` (`ring` provider) + `tokio-rustls` | `netkit-tls` | Safe, modern TLS; pluggable `ResolvesServerCert` for SNI; `ring` keeps the build to Rust and a C compiler |
| Cert parsing | `rustls-pemfile`, `x509-parser` | `netkit-tls` | PEM loading and not-after extraction |
| Upstream trust roots | `rustls-native-certs` | `netkit-tls` | The system's trust store; roots that cannot be parsed are skipped |
| Name resolution | the system resolver, through `tokio` | `netkit-dns` | Names resolved as every program on the machine resolves them, behind a cache; no DNS spoken |
| Socket options | `socket2` | `netkit-listen` | TCP keepalive timing, which tokio does not expose, without `unsafe` |
| Config serialization | `serde` + `toml` + `serde_json` | `gfe-config` (`serde_json` also `gfe-proxy`, for the last-known-good cache) | TOML bootstrap, JSON dynamic config |
| File watching | `notify` | `gfe-proxy` | inotify-based hot reload |
| Atomic config swap | `arc-swap` | `gfe-proxy`, `netkit-tls`, `netkit-listen` | Lock-free snapshot reads on the hot path |
| Concurrent maps | `dashmap` | `netkit-health-checking`, `netkit-dns` | The health map and the address cache, read from the data plane |
| Metrics | `prometheus-client` | `netkit-observability` | Direct Prometheus exposition; the metric types are re-exported |
| Logging | `tracing` (all); `tracing-subscriber` + `tracing-appender` | `netkit-observability` | Structured events; a writer thread so the log never blocks |
| eBPF | a C program built with clang; `aya` to load it | `netkit-kernel` | Pure-Rust loader, no libbpf, static musl builds keep working |
| System calls | `rustix` | `netkit-kernel`, `netkit-listen`, `gfe-node` | The monotonic clock, passing sockets between processes, the node's own process calls, without `unsafe` |
| Randomness | `rand` | `gfe-proxy`, `netkit-load-balancing` | Request ids; weighted selection |
| CLI | `clap` | `gfe-node` | Arg parsing |
| Error handling | `thiserror`, `anyhow` | libraries, `gfe-node` | Library vs. binary error idioms |
| Testing | `cargo test` / `cargo-nextest`; `hyper`, `rustls` and `rcgen` as the peer on the other side of the wire | `tests/` of each crate | Socket-level functional tests without physical backends |
| Benchmarks | `criterion` | `gfe-proxy`, `netkit-load-balancing`, `netkit-tls` | Routing, selection and handshake micro-benchmarks |
| Load generator | `hyper` | `gfe-loadtest` | End-to-end load tests (`hack/loadtest.sh`) |
| Build requirements | a C compiler (for `ring`), `clang` on Linux (the eBPF program) | | |

The `gfe-node` binary is built from 207 crates, 12 of them this repository's.

---

*Based on: Google's Front End service (Google infrastructure security design).*
