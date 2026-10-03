# General Front End (GFE) — Design Specification v0.1

> Inspired by Google's Front End (GFE) service. This document specifies **General Front End**, a Rust-implemented, L7 TLS-terminating HTTP reverse proxy designed to sit directly behind the [`lb`](https://github.com/thewillyhuman/lb) Maglev L4 load balancer. GFE is the L7 layer that `lb`'s specification (Section 11) anticipates but deliberately leaves unspecified.

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
11. [L4 Load Balancer Integration](#11-l4-load-balancer-integration)
12. [Observability](#12-observability)
13. [Failure Modes and Resilience](#13-failure-modes-and-resilience)
14. [Operational Considerations](#14-operational-considerations)
15. [Implementation Roadmap](#15-implementation-roadmap)
16. [Technology Stack](#16-technology-stack)

---

## 1. Goals and Non-Goals

### Goals

- Provide a **centralized, shared L7 reverse-proxy and TLS-termination service** for all teams, so individual teams never manage certificates, TLS policy, or HTTP edge concerns themselves.
- **Terminate TLS** on behalf of every service behind a single set of VIPs, with **SNI-based certificate selection** from a centrally managed certificate store.
- Enforce a **uniform TLS policy** (minimum protocol version, approved cipher suites, HSTS) centrally, so security posture is consistent across all services.
- **Route HTTP requests** to the correct upstream pool based on the SNI / `Host` header and request path.
- Maintain **long-lived, pooled upstream connections** to application backends, amortizing TLS handshake and TCP setup cost across many client requests.
- Perform **L7 health checking** (HTTP/HTTPS) of upstreams — richer than the L4 LB's connectivity checks — and route only to healthy upstreams.
- Support **zero-downtime backend deploys** via lame-duck draining: an upstream signals readiness to drain and GFE stops sending it new requests while in-flight requests complete.
- Be **fully stateless**: a GFE node's behaviour is a pure function of its configuration. Any node can be added, removed, or restarted without coordination.
- Be **configured entirely from a local file**, hot-reloaded atomically (same model as `lb`, [ADR-001](https://github.com/thewillyhuman/lb/blob/main/.docs/adr-001-configuration-model.md)).
- Expose **rich metrics and structured logs** for monitoring.
- Be **minimal**: implement only the features that genuinely add value as a shared edge. No knobs that a single team could trivially manage themselves.

### Non-Goals

- GFE is **not an L4 load balancer**. Spreading client traffic across GFE nodes is the job of the `lb` Maglev layer in front of it. GFE does not speak BGP and does not do packet forwarding.
- GFE is **not a kernel-bypass data plane**. Unlike `lb`, GFE terminates TCP and TLS and therefore uses the kernel network stack and ordinary async sockets. There is no AF_XDP path.
- GFE is **not a WAF or DDoS scrubber**. It performs basic edge hygiene (connection/header limits, timeouts) but is not a security inspection engine.
- GFE is **not a CDN / cache**. It does not store response bodies. (Caching is a possible future layer, explicitly out of scope here.)
- GFE does **not host application logic**. It proxies; it does not serve content beyond minimal synthetic error responses and its own health/metrics endpoints.
- GFE is **not a service mesh sidecar**. It is a centralized fleet, not a per-pod proxy.
- GFE does **not own certificate issuance policy**. It consumes certificates from a store and (future) renews them via ACME; the CA trust decisions live elsewhere.

---

## 2. Architecture Overview

GFE is the L7 tier in a two-tier edge. The L4 `lb` fleet spreads packets across GFE nodes; GFE terminates TLS and proxies HTTP to application backends.

```
                        Internet / internal clients
                                      |
                              [ BGP Router ]
                                      |
                    ECMP across all L4 LB nodes
                    /           |           \
              [LB Node 1]  [LB Node 2]  [LB Node 3]        ← lb: Maglev L4, GRE encap
                    \           |           /
                     GRE-encapsulated packets
                     (VIP = the GFE service VIP)
                    /           |           \
              [GFE Node 1]  [GFE Node 2]  [GFE Node 3]     ← this project: L7 TLS + HTTP
               |  TLS terminate, route, proxy  |
               |  pooled upstream connections  |
                    \           |           /
          [App Backend A]  [App Backend B]  [App Backend C]
              any IP service domain, any team

        Responses: GFE → client directly (DSR relative to the L4 LB).
        The L4 LB is never on the return path. The GFE *is* the TCP/TLS
        endpoint for the client, and the originating proxy for upstreams.
```

A GFE node has two logical components, mirroring `lb`'s forwarder/controller split:

- **Proxy (data plane).** Accepts client connections on the service VIP, terminates TLS, parses HTTP, selects a route and an upstream backend, and proxies the request/response over a pooled upstream connection. Fully async (Tokio).
- **Controller (control plane).** Watches the config file, validates and atomically swaps in new configuration, health-checks upstreams, manages the certificate store, and drives lame-duck draining.

The two communicate only through **atomic pointer swaps** (`ArcSwap`) of the shared routing/upstream snapshot and certificate store, and a shared health status map. There is no other shared mutable state, and there is no coordination between GFE nodes.

---

## 3. Project Structure

The codebase is a Cargo workspace with strict separation of concerns, following the exact conventions of its sibling `lb`. Each crate has a single responsibility; dependencies flow inward, with `gfe-types` at the root of the DAG. Binary crates depend on library crates, never the reverse.

```
gfe/
├── Cargo.toml                          # Workspace root
├── Cargo.lock
├── README.md
├── rust-toolchain.toml
├── Dockerfile
├── deny.toml
├── .docs/
│   ├── spec.md                         # This specification
│   ├── adr-001-configuration-model.md  # File-based config (inherits lb's rationale)
│   ├── adr-002-tls-termination-model.md# rustls, SNI resolver, cert store design
│   ├── installation.md
│   └── operations.md
│
├── config/
│   └── gfe.example.toml                # Reference node (bootstrap) configuration
│
│  ─────────────────────────────────────
│  DOMAIN LAYER — pure types and traits, no I/O, no frameworks
│  ─────────────────────────────────────
│
├── crates/
│   ├── gfe-types/                  # Canonical domain types
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── listener.rs              # Listener, ListenProtocol (http|https)
│   │       ├── route.rs                 # Route, HostMatch, PathMatch, RouteAction
│   │       ├── upstream.rs              # Upstream, UpstreamPool, LbPolicy, Scheme, HealthStatus
│   │       ├── tls.rs                   # TlsPolicy, CertRef, MinVersion
│   │       └── config.rs                # NodeConfig (bootstrap) + DynamicConfig (routes/pools/certs)
│   │
│   ├── gfe-router/                 # L7 route matching: (host, path, headers) → upstream pool
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                   # RouteTable: compiled, immutable, atomically swappable
│   │       ├── matcher.rs               # Host (exact + wildcard) and path (prefix/exact) matching
│   │       └── snapshot.rs              # Compiled routing snapshot built from DynamicConfig
│   │
│   │  ─────────────────────────────────
│   │  DATA PLANE — async Tokio proxy engine
│   │  ─────────────────────────────────
│   │
│   ├── gfe-tls/                    # TLS termination support
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── cert_store.rs            # SNI → certified key map, atomically swappable
│   │       ├── resolver.rs             # rustls ResolvesServerCert backed by cert_store
│   │       ├── policy.rs                # ServerConfig builder: versions, ciphers, ALPN
│   │       └── loader.rs                # PEM cert/key parsing, expiry extraction
│   │
│   ├── gfe-upstream/               # Upstream pools, LB policy, connection pooling
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── pool.rs                  # UpstreamPoolHandle: healthy-set view + LB policy
│   │       ├── policy.rs                # RoundRobin, LeastRequest, RingHash (affinity)
│   │       ├── conn_pool.rs             # Per-backend idle connection pool (h1 + h2)
│   │       └── client.rs                # hyper-based upstream client, TLS to upstream
│   │
│   ├── gfe-proxy/                  # L7 proxy engine (the data plane)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                   # Shared data-plane state (ProxyShared)
│   │       ├── listeners.rs             # Listening sockets, reconciled on reload
│   │       ├── acceptor.rs              # Per-socket accept loop, connection limits
│   │       ├── connection.rs            # Per-connection: TLS handshake → HTTP serve
│   │       ├── activity.rs              # In-flight tracking for client timeouts
│   │       ├── service.rs               # Per-request: route → select upstream → proxy
│   │       ├── forward.rs               # Request/response streaming, header rewriting
│   │       ├── errors.rs                # Synthetic error responses (4xx/5xx pages)
│   │       └── drain.rs                 # Graceful connection draining on shutdown/reload
│   │
│   │  ─────────────────────────────────
│   │  CONTROL PLANE — async, Tokio-based
│   │  ─────────────────────────────────
│   │
│   ├── gfe-health/                 # L7 upstream health checking
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── checker.rs               # HealthChecker: runs probes, deduplicates by (ip,port,probe)
│   │       ├── probe.rs                 # Probe trait + HttpProbe, HttpsProbe, TcpProbe
│   │       └── state_machine.rs         # UNKNOWN → HEALTHY ↔ UNHEALTHY (+ DRAINING via lame duck)
│   │
│   ├── gfe-config/                 # Config loading, validation, watching, atomic apply
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── loader.rs                # Read + deserialize bootstrap TOML and dynamic JSON
│   │       ├── validator.rs             # Semantic validation (dangling pool refs, cert refs, etc.)
│   │       ├── applier.rs               # Compile snapshot, atomic ArcSwap of router + cert store
│   │       ├── watcher.rs               # notify (inotify) watcher on config + cert files
│   │       └── cache.rs                 # Last-known-good cache for restart resilience
│   │
│   ├── gfe-controller/             # Control-plane orchestrator
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                   # Controller public API
│   │       └── orchestrator.rs          # Coordinates config, health, cert lifecycle
│   │
│   │  ─────────────────────────────────
│   │  OBSERVABILITY
│   │  ─────────────────────────────────
│   │
│   ├── gfe-metrics/                # Metrics registration and exposition
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── proxy_metrics.rs         # Connections, requests, latency, bytes
│   │       ├── control_metrics.rs       # Health, config reload, cert expiry
│   │       ├── process_metrics.rs       # File descriptors, CPU, memory, runtime
│   │       └── kernel_metrics.rs        # What the kernel reports (eBPF)
│   │
│   ├── gfe-ebpf/                   # Kernel view of the node's TCP connections (optional)
│   │   ├── build.rs                     # Compiles the kernel program with clang
│   │   ├── bpf/tcp_events.bpf.c         # The eBPF program (sockops, cgroup-attached)
│   │   └── src/
│   │       ├── lib.rs                   # Types; why it may be unavailable
│   │       ├── wire.rs                  # Byte layouts shared with the program
│   │       ├── linux.rs                 # Load, attach, read
│   │       └── unsupported.rs           # Stand-in elsewhere
│   │
│   ├── gfe-handover/               # Passing a node's listening sockets to its successor
│   │   └── src/
│   │       └── lib.rs                   # The exchange over a Unix socket (Unix only)
│   │
│   │  ─────────────────────────────────
│   │  BINARIES
│   │  ─────────────────────────────────
│   │
│   ├── gfe-node/                   # Main binary: proxy + controller on one box
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── main.rs                  # CLI args, config load, spawn proxy & controller
│   │
│   └── gfe-trace/                  # Binary: CLI request tracer
│       ├── Cargo.toml
│       └── src/
│           └── main.rs                  # Send a marked request, print the routing decision
│
├── tests/
│   ├── integration/
│   │   ├── tls_termination_test.rs      # SNI selection, ALPN, min-version enforcement
│   │   ├── routing_test.rs              # Host/path → upstream pool selection
│   │   ├── proxy_test.rs                # End-to-end request proxying (mock upstreams)
│   │   ├── health_test.rs               # Upstream failover on health change
│   │   ├── lame_duck_test.rs            # Draining upstream stops receiving new requests
│   │   └── config_reload_test.rs        # Hot config + cert swap under load
│   └── benchmarks/
│       ├── routing_bench.rs             # Route match throughput
│       └── tls_handshake_bench.rs       # Handshakes/sec, session resumption
│
└── deploy/
    ├── gfe-node.service                 # systemd unit
    ├── generate-config.sh               # Generate dynamic config JSON scaffold
    ├── validate-config.sh               # Validate config before deployment
    ├── backend-onboard.sh               # GRE tunnel + loopback VIP on a GFE node
    └── grafana/
        └── gfe-dashboard.json           # Pre-built Grafana dashboard
```

### Design Principles Behind the Structure

**Single Responsibility per Crate.** `gfe-router` knows how to match a request to an upstream pool but nothing about TLS or sockets. `gfe-tls` knows how to resolve and present certificates but nothing about routing. `gfe-upstream` knows how to pick and connect to a backend but nothing about how the request arrived.

**Dependency Direction: Inward Only.** Library crates depend only on `gfe-types` and lower-layer libraries. `gfe-node` is the only crate that wires everything together. The graph is a DAG rooted at `gfe-types`.

```
                       gfe-node (binary)
                      /                \
              gfe-proxy            gfe-controller
             /    |    \           /      |       \
      gfe-tls gfe-router gfe-upstream  gfe-health gfe-config
            \      |        |    /        |        /
             ──────── gfe-metrics ───────
                          |
                      gfe-types
```

**Stateless by Construction.** No GFE crate persists request, session, or connection state across process restarts. The certificate store, route table, and upstream health are all derived from configuration plus live probing. Connection pools are ephemeral, per-node optimizations. This is what makes a GFE node interchangeable with any other.

**Atomic, Lock-Free Config Swaps.** Like `lb`, the live routing snapshot and certificate store are held behind `ArcSwap`. A config reload compiles a brand-new snapshot off the hot path, then swaps the pointer in a single atomic store. In-flight requests keep using the old snapshot until they complete; new requests pick up the new one. The data plane never blocks on the control plane.

**Tests Live Close to What They Test.** Unit tests are `#[cfg(test)] mod tests` inside each crate. Cross-crate and socket-level tests live in the top-level `tests/`. Benchmarks use `criterion` in `tests/benchmarks/`.

---

## 4. Request Model

GFE's configuration is built from four primitives.

### Listeners

A **listener** binds an address and port and accepts client connections.

- `protocol`: `https` (TLS-terminating) or `http` (plaintext — used for HTTP→HTTPS redirect listeners or internal-only VIPs).
- For `https` listeners, a `TlsPolicy` and the certificate store apply.
- The bind address is normally the **service VIP** (configured on the loopback for DSR; see Section 11), so that GRE-decapsulated packets from the L4 LB reach the GFE socket.

### Routes

A **route** maps an incoming request to an action.

- **Match** on:
  - `host`: exact (`api.example.org`) or single-label wildcard (`*.example.org`). For HTTPS the host is taken from the validated SNI and cross-checked against the `Host`/`:authority`; for HTTP from the `Host` header.
  - `path`: prefix (`/api/`) or exact (`/healthz`). Most specific match wins (longest path prefix, exact host over wildcard).
  - optional `headers`: presence/exact-value matches (kept minimal).
- **Action**: forward to a named **upstream pool**, or return a fixed redirect (e.g. HTTP→HTTPS) or a fixed status.
- Routes are evaluated against a compiled, immutable `RouteTable` snapshot for O(1)–O(log n) matching.

### Upstream Pools

An **upstream pool** is a named set of application backends serving the same role.

- Each **upstream** is `host:port` plus optional `weight`.
- `scheme`: how GFE talks to the pool's backends, independent of the client-facing protocol: `http` (cleartext HTTP/1.1), `https` (TLS; HTTP/2 or HTTP/1.1 by ALPN) or `h2c` (cleartext HTTP/2 with prior knowledge, for backends that speak only HTTP/2 without TLS, typically gRPC servers).
- `lb_policy`: how requests are distributed across healthy upstreams (Section 6.5).
- `health_check`: L7 probe config (Section 7.1).
- Pools may be **referenced by multiple routes**. Health checks are deduplicated across pools by `(ip, port, probe)`.

### Certificates

A **certificate** entry binds one or more SNI names to a PEM certificate chain + private key on disk.

- Supports exact names and single-label wildcards (`*.example.org`).
- An optional `default` certificate handles connections whose SNI matches nothing (or clients that send no SNI).
- Certificates are loaded into the in-memory cert store and watched for change (Section 7.3).

---

## 5. Request Flow

```
 1. Client opens a TCP connection to the service VIP:443.
 2. Router ECMP-hashes the 5-tuple → one L4 LB node.
 3. L4 LB Maglev-selects a GFE node, GRE-encapsulates the packet, forwards it.
 4. GFE node's GRE interface decapsulates → packet enters the kernel addressed
    to the VIP on the GFE's loopback. The kernel TCP stack accepts it.
 5. GFE acceptor (acceptor.rs) accepts the TCP connection (subject to limits).
 6. TLS handshake (connection.rs → gfe-tls):
    a. ClientHello arrives; the SNI resolver (resolver.rs) selects a certificate
       from the cert store (cert_store.rs) by SNI, falling back to default.
    b. TLS policy (policy.rs) enforces min version + cipher suites; ALPN
       negotiates h2 or http/1.1.
 7. HTTP serving (connection.rs via hyper):
    For each request on the connection:
    a. Routing (service.rs → gfe-router): match (host, path, headers) → action.
       - No match → 404 synthetic response (errors.rs).
       - Redirect/fixed action → respond directly.
       - Forward action → continue.
    b. Upstream selection (gfe-upstream): from the route's pool, pick a healthy
       backend via the pool's LB policy.
    c. Connection acquisition (conn_pool.rs): reuse a pooled idle upstream
       connection or open a new one (TLS to upstream if scheme=https).
    d. Forwarding (forward.rs): rewrite hop-by-hop headers, add forwarding
       headers (X-Forwarded-For/-Proto, Forwarded, X-Request-Id), stream the
       request body to the upstream, stream the response body back to the client.
 8. Response goes from the GFE directly to the client.
    - Source IP is the VIP (DSR relative to the L4 LB). The L4 LB is NOT on the
      return path. The GFE is the TCP/TLS endpoint, so it owns the return leg.
 9. Connection reuse: client keep-alive / h2 connection is retained; upstream
    connection is returned to the idle pool for the next request.
```

---

## 6. Proxy Design (Data Plane)

> **Code location:** `crates/gfe-proxy/` (engine) + `crates/gfe-tls/`, `crates/gfe-router/`, `crates/gfe-upstream/`

The proxy is a fully asynchronous Tokio service. Unlike `lb`'s forwarder, it terminates TCP and TLS and therefore uses the kernel stack and ordinary `tokio::net` sockets — there is no kernel bypass and no per-packet hot path to keep allocation-free. The performance discipline instead targets **per-request** overhead: zero-copy body streaming, connection reuse, and lock-free config reads.

### 6.1 Listeners and Acceptors

> **Code location:** `crates/gfe-proxy/src/listeners.rs`, `crates/gfe-proxy/src/acceptor.rs`

One accept loop runs per configured listener. Each loop:

1. Binds the listener address (`TcpListener`) with `SO_REUSEADDR`; `TCP_NODELAY` is set on accepted sockets.
2. Accepts connections and enforces a **global and per-listener max concurrent connection limit**. When the limit is hit, new connections are accepted and immediately closed (counted via `gfe_connections_rejected_total`) rather than being left to pile up in the backlog.
3. Spawns one Tokio task per accepted connection (`connection.rs`). The accept loop never blocks on per-connection work.
4. Applies an **accept-to-first-byte / handshake timeout** so slow-loris-style connections that never make progress are reaped early.

The set of active listeners is part of the config snapshot and is reconciled on every reload (`listeners.rs`). A listening socket is identified by its **address and port**; a listener's id and protocol are read per accepted connection, so they can change without rebinding. On reload:

- sockets for addresses the new config adds are bound **first** — if any cannot be bound the whole reload is rejected and nothing changes;
- sockets the new config no longer names stop accepting (connections already accepted on them run to completion);
- sockets whose address is unchanged are left untouched, so a reload never causes an accept gap.

Two listeners may not share an address and port (rejected by validation).

### 6.2 TLS Termination and SNI Certificate Resolution

> **Code location:** `crates/gfe-tls/`

GFE terminates TLS with **rustls**. Centralized certificate management is GFE's core value proposition.

**Certificate store (`cert_store.rs`).** An immutable map from SNI name → `Arc<CertifiedKey>` (parsed chain + signing key), plus an optional default. Wildcard names (`*.example.org`) are matched after exact names. The store is held behind `ArcSwap`; the certificate manager (Section 7.3) builds a new store and swaps it atomically, so a cert rotation never interrupts in-flight handshakes.

**SNI resolver (`resolver.rs`).** Implements rustls's `ResolvesServerCert`. On each `ClientHello` it reads the current store (a single atomic load), looks up the SNI, and returns the certified key. Lookup order: exact SNI → wildcard SNI → default cert. A miss is counted (`gfe_tls_sni_no_cert_total`) and the handshake is failed cleanly.

**TLS policy (`policy.rs`).** Builds the rustls `ServerConfig`: minimum protocol version (default TLS 1.2, configurable to 1.3-only), the approved cipher-suite / signature-scheme set, session resumption, and ALPN advertisement (`h2`, `http/1.1`). See Section 9.

**Stateless session resumption.** TLS session tickets use **operator-provided ticket keys** shared across the fleet (from config / a secret file), so a resumed session that lands on a different GFE node than the original (a new connection hashes to a different node under Maglev) still resumes. Without shared keys, resumption degrades to full handshakes across nodes but remains correct. Keys are rotated by config reload.

### 6.3 HTTP Protocol Handling

> **Code location:** `crates/gfe-proxy/src/connection.rs`

After the handshake, the connection is served by **hyper**:

- **Downstream protocols:** HTTP/1.1 and HTTP/2. On HTTPS listeners the version is selected by ALPN; plaintext listeners detect HTTP/2 by its connection preface (prior knowledge), which is what cleartext gRPC clients use. HTTP/1.0 is accepted but kept alive only when the client opts in.
- **Keep-alive / multiplexing:** h1 keep-alive and h2 multiplexing are honored; each request on the connection is routed independently.
- **Limits:** max header size, max concurrent h2 streams, and request/idle timeouts are enforced per connection (Section 6.8).
- **Normalization:** `Host` / `:authority` is validated and, for HTTPS, cross-checked against the negotiated SNI; conflicting or absent authority yields a 400.

### 6.4 Routing

> **Code location:** `crates/gfe-router/`

Routing maps a request to an action using a compiled, immutable snapshot.

- The `RouteTable` (`snapshot.rs`) is compiled from `DynamicConfig` at reload time: host matches are bucketed (exact map + wildcard list), and within a host, paths are stored for **longest-prefix / exact** resolution.
- Match precedence: exact host beats wildcard host; within a host, exact path beats the longest matching prefix.
- The table is read via `ArcSwap` — a single atomic load per request, no lock.
- A non-match returns a synthetic `404` (`errors.rs`). A matched `Redirect` or `Fixed` action is answered directly without touching an upstream (this is how HTTP→HTTPS redirect listeners work).

### 6.5 Upstream Selection and Load Balancing

> **Code location:** `crates/gfe-upstream/src/pool.rs`, `crates/gfe-upstream/src/policy.rs`

Once a route resolves to a pool, GFE selects one **healthy** upstream. The pool exposes only the current healthy set (driven by the health checker, Section 7.1); draining upstreams (lame duck, Section 7.4) are excluded from new selection.

Supported policies (minimal but sufficient):

| Policy | Use case |
|---|---|
| `round_robin` (default) | Even distribution across equal backends. |
| `least_request` | Prefer the backend with the fewest in-flight requests; better under heterogeneous request cost. |
| `ring_hash` | Consistent-hash on a configured key (client IP, a header, or a cookie) for **session affinity**. Reuses a Maglev/ketama-style ring so backend changes disturb minimal traffic — conceptually the same property `lb-hashing` provides at L4, applied here at L7. |

Weights are honored by `round_robin` and `ring_hash`. If a pool has **no healthy upstreams**, GFE returns `503` and increments `gfe_no_healthy_upstream_total`.

### 6.6 Upstream Connection Pooling

> **Code location:** `crates/gfe-upstream/src/conn_pool.rs`, `crates/gfe-upstream/src/client.rs`

Long-lived pooled upstream connections are a primary reason to run a shared edge: they amortize TCP + TLS handshake cost across all client requests to a backend.

- **Per-backend idle pools.** Keyed by `(scheme, host, port)`. Idle connections are reused; the pool caps idle count and idle age per backend. HTTP/2 upstream connections (`https` via ALPN, or `h2c`) are multiplexed: many concurrent requests share one connection per backend.
- **HTTP/1.1 and HTTP/2 upstreams.** For h2 upstreams, a single connection multiplexes many concurrent requests (subject to the upstream's `SETTINGS_MAX_CONCURRENT_STREAMS`); for h1, one request per connection at a time.
- **Upstream TLS (`client.rs`).** When `scheme=https`, GFE validates the upstream certificate against a configured trust store (system roots or a pinned CA). Optional mTLS (client cert to upstream) is supported for zero-trust backends.
- **Health-aware eviction.** When a backend transitions to UNHEALTHY or DRAINING, its idle connections are dropped and no new ones are opened.
- **Bounded (`limit.rs`).** Open upstream connections are capped node-wide at `max_upstream_connections`, to protect both GFE and the backends from connection storms after a reload or failover. The cap is enforced where connections are opened: a request that finds a pooled connection is unaffected, one that would need a new connection beyond the cap is answered at once with a `503` (`error=upstream_connection_limit`), without retrying and without counting against the backend. Connections are counted for as long as their socket is open, idle ones included.

### 6.7 Request and Response Forwarding

> **Code location:** `crates/gfe-proxy/src/forward.rs`

Forwarding streams bodies without buffering them in full:

- **Hop-by-hop headers** (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade`, `TE`, `Proxy-*`, etc.) are stripped per RFC 9110. The one exception is a `TE` of exactly `trailers`, which is passed on: GFE does relay trailers, and gRPC requires the header.
- **Forwarding headers** are added/normalized: `X-Forwarded-For` (append client IP), `X-Forwarded-Proto`, `X-Forwarded-Host`, `Forwarded`, and a generated `X-Request-Id` (propagated if the client supplied a valid one) for end-to-end tracing.
- **Streaming.** Request and response bodies are streamed (`http-body`), so large uploads/downloads do not consume proportional memory. Backpressure flows naturally through the async body.
- **HSTS** (`Strict-Transport-Security`) is injected on HTTPS responses per TLS policy.
- **Protocol translation.** Client h2 ↔ upstream h1 (and vice versa) is handled transparently by hyper at the request/response abstraction level.
- **gRPC.** A gRPC call is an HTTP/2 request whose status travels in the response trailers, so it needs HTTP/2 on both legs and nothing buffered in between. GFE proxies unary and streaming calls (client-, server- and bidirectional) when the client connects over HTTP/2 and the pool's scheme is `https` (the backend selects `h2` by ALPN) or `h2c` (Section 4). Messages are relayed frame by frame in both directions and trailers are passed through. gRPC calls are `POST`s, so they are never retried, and they are not subject to the response timeouts (Section 6.8). When GFE itself fails a call (no route, no healthy upstream, backend unreachable, connection limit) it answers in gRPC's terms: a trailers-only response, HTTP `200` with `grpc-status` and a `grpc-message` of `gfe: <reason>`, the reason being the access log's `error` value. The status is the one gRPC's HTTP mapping assigns to the HTTP status GFE would otherwise have sent: `UNIMPLEMENTED` (12) for an unrouted call, `UNAVAILABLE` (14) for everything a `502`/`503`/`504` stands for. Such calls therefore count as `status="200"` in `gfe_requests_total` and by their `grpc_status` in `gfe_grpc_responses_total`.

### 6.8 Timeouts, Retries, and Limits

> **Code location:** `crates/gfe-proxy/src/service.rs`, `crates/gfe-proxy/src/connection.rs`

Bounded, predictable behaviour under stress:

- **Timeouts:** TLS handshake, request header, upstream connect, upstream first-byte, and overall request timeouts — all configurable, with safe defaults.
- **Upstream timeouts (`progress.rs`, `forward.rs`).** Three timeouts bound the wait for a backend's response headers; none of them ever cuts a response that has started:
  - `upstream_connect` — establishing the TCP connection.
  - `upstream_first_byte` — per attempt: the backend must start responding within this long of having last been sent something, be it the request or a piece of its body. An upload therefore never times out while it progresses. If the wait expires while the request body is still incomplete, it is the client that stalled: it gets a `408` and the backend is not counted as failing. Otherwise the client gets a `504`.
  - `request_total` — across attempts: once the request has been sent in full, a response must arrive within this long, however many backends are tried.

  **gRPC calls are exempt** from `upstream_first_byte` and `request_total`: a streaming call may have nothing to send, not even headers, for as long as it likes. How long a call may take is the deadline its client sets (`grpc-timeout`, which GFE forwards) and enforces by cancelling. What the timeouts would have caught, a backend that died, is caught by **HTTP/2 keep-alive** on the upstream connection instead: a connection with requests in flight that has been silent for `upstream_first_byte` is pinged, and if the ping is not answered within `upstream_connect` the connection is closed and its calls fail.
- **Client timeouts (`activity.rs`, `connection.rs`).** A request is *in flight* from its parsed head until its response body is fully written. Two timeouts are derived from that:
  - `request_header` — the **first** request head must arrive within this long of the connection being established (after the TLS handshake), else the connection is dropped. This bounds connections that never send, or drip, a request.
  - `client_idle` — a connection with **no request in flight** for this long is shut down gracefully (HTTP/2 clients receive a `GOAWAY`). On HTTP/1 this covers the keep-alive wait *and* the time to receive the next request head, since hyper runs one timer over both. A connection with a request in flight is never closed by these timeouts, however slow the upstream or the transfer.
- **Retries (conservative).** Only **idempotent** requests (per method, and only when the request body has not yet been streamed) are retried, and only on **connection-establishment / pre-response** failures, with a small bounded retry budget. GFE never retries after any response bytes have been forwarded. This avoids amplifying load during incidents.
- **Limits:** max header bytes (`431` when exceeded; at least 8192), max concurrent connections (global + per listener), max concurrent h2 streams, and max upstream connections. Exceeding a limit yields a clean `4xx`/`5xx` (or connection refusal) and a counter — never unbounded growth.
- **Synthetic errors (`errors.rs`).** GFE emits compact, consistent error responses (404 no-route, 408 stalled upload, 502 upstream error, 503 no-healthy-upstream / overloaded, 504 timeout) with a request id, suitable for debugging without leaking internals. To a gRPC caller the same failures are sent as a `grpc-status` (Section 6.7).

---

## 7. Controller Design (Control Plane)

> **Code location:** `crates/gfe-controller/` (orchestrator) + `crates/gfe-health/`, `crates/gfe-config/`, `crates/gfe-tls/`

The controller runs as Tokio tasks alongside the proxy. It does not handle client requests and shares with the proxy only atomic snapshots (route table, cert store) and the upstream health map.

### 7.1 L7 Health Checking

> **Code location:** `crates/gfe-health/`

GFE health-checks every upstream in every referenced pool — at **L7**, which is richer than the L4 LB's TCP/connectivity checks.

Each probe implements the `Probe` trait:

```rust
/// crates/gfe-health/src/probe.rs
#[async_trait]
pub trait Probe: Send + Sync {
    async fn check(&self, target: &Upstream, timeout: Duration) -> ProbeResult;
}
```

| Type | Implementation | Success criterion |
|---|---|---|
| `http`  | `HttpProbe`  | GET a configurable path; 2xx (configurable expected status / body substring). |
| `https` | `HttpsProbe` | Same over TLS; certificate validation configurable. |
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

**Deduplication (`checker.rs`).** A backend appearing in multiple pools is probed once per `(ip, port, probe)`; the result is shared across all referencing pools. A check changed by a reload restarts the probe of every backend it applies to; the backend keeps its current status until the new probe's thresholds say otherwise.

**State machine (`state_machine.rs`):**

```
UNKNOWN   → (healthy_threshold successes)   → HEALTHY
HEALTHY   → (unhealthy_threshold failures)  → UNHEALTHY
UNHEALTHY → (healthy_threshold successes)   → HEALTHY
(any)     → (lame-duck signal)              → DRAINING   (Section 7.4)
```

Health is written to a shared `DashMap<(IpAddr, u16), HealthStatus>` read by the data plane on each upstream selection. Because selection consults the live map (not a cached snapshot), a backend going UNHEALTHY stops receiving new requests immediately, with no rebuild step required — the pool simply presents a smaller healthy set on the next selection.

Since all upstreams have globally routable IPs across the organization's IP service domains (same model as `lb`), the health checker reaches each upstream directly with no per-domain configuration.

### 7.2 Config Manager

> **Code location:** `crates/gfe-config/`

Responsibilities:

1. **Load** (`loader.rs`) the bootstrap node config (TOML) once at startup, and the dynamic config (JSON: listeners, routes, pools, certificates) at startup and on every change.
2. **Validate** (`validator.rs`) before applying: every route references an existing pool; every listener/route references a loadable certificate (for HTTPS); no duplicate listener binds; host/path patterns well-formed; ports in range; cert and key files parse and match. Invalid config is **rejected wholesale** — the running snapshot is kept.
3. **Apply atomically** (`applier.rs`): compile a new `RouteTable` + cert store off the hot path, then swap both via `ArcSwap`. In-flight requests finish on the old snapshot; new requests use the new one. Listener add/remove is reconciled around the swap by the controller (Section 6.1).
4. **Watch** (`watcher.rs`, `cert_files.rs`): `notify` (inotify on Linux) on the dynamic config file, with a debounce window that coalesces rapid successive writes (e.g. an editor writing in chunks) into a single reload. The certificate and key files the config names are **polled every 10 s** by `stat` (inode, size, mtime, ctime) rather than watched: their set changes with every reload and they are commonly swapped via rename or symlink, which a poll handles uniformly. A change triggers the same validated reload.
5. **Cache** (`cache.rs`): persist the last-known-good dynamic config locally. A node that starts while the deployed dynamic config is missing, invalid or cannot be applied (e.g. a listener that cannot be bound) starts from the cache instead, so a restart behaves like a rejected reload: what was served before keeps being served. It reports this as `gfe_config_from_cache = 1` and leaves the cache with the next successful reload. Without a cache, or with an unusable one, the node refuses to start.

The file-based model and its rationale are inherited verbatim from `lb`'s ADR-001: no central API, no shared runtime state, deployment of the file is the orchestration layer's job (Puppet/Ansible/git), and all nodes converge by being given the same file.

### 7.3 Certificate Manager

> **Code location:** `crates/gfe-tls/src/cert_store.rs`, `crates/gfe-tls/src/loader.rs`

- On config load and on cert-file change, the manager parses each certificate entry (`loader.rs`), builds an updated cert store, and swaps it in atomically.
- It records each certificate's **not-after** time and exposes `gfe_cert_expiry_timestamp{sni}` so monitoring can alert well before expiry.
- A certificate that fails to parse or whose key does not match is rejected without disturbing the currently served store; the failure is logged and counted. A rotation caught between the two file writes is therefore harmless: the old certificate keeps being served until the matching key lands, which triggers the next reload.

**Automated renewal (ACME) — Phase 3, high value.** Because certificate management is GFE's reason to exist, automated issuance/renewal via ACME (e.g. `instant-acme`) is a planned addition: GFE answers `http-01` (via a built-in `/.well-known/acme-challenge/` route on the HTTP listener) or `tls-alpn-01` challenges, obtains/renews certs ahead of expiry, writes them to the cert store, and hot-swaps — with zero team involvement after initial registration. This is specified as a follow-up so the MVP can ship with operator-provided certificates first.

### 7.4 Lame Duck and Graceful Drain

> **Code location:** `crates/gfe-health/src/state_machine.rs`, `crates/gfe-proxy/src/drain.rs`

**Upstream lame duck (zero-downtime backend deploys).** A backend signals it wants to drain — by serving a configured **lame-duck response** on its health endpoint (e.g. a `503` with a known marker, or a dedicated drain path) — and the health state machine moves it to `DRAINING`. While draining:

- The backend is removed from the **new-request** selection set, so it receives no new requests.
- Existing pooled connections and in-flight requests complete normally.
- Idle pooled connections to it are closed.

This lets teams deploy without resetting live requests.

**GFE node graceful drain (`drain.rs`).** On `SIGTERM` or operator command, a GFE node:

1. Fails its own `/readyz` so the L4 LB's health check withdraws it from the GFE pool, and the L4 LB stops Maglev-selecting it for **new** connections.
2. Stops accepting new client connections.
3. Asks the clients of its open connections to leave, in a way that loses no request:
   - a connection with a request in flight is shut down gracefully at once: the request is answered, an HTTP/2 client is sent a `GOAWAY`, and an HTTP/1 response carries `Connection: close`;
   - a connection with no request in flight is given half the drain deadline to send one more, which is answered the same way. Closing it at once would race with a request the client has already sent. If none comes it is closed, as an idle timeout would close it.
4. Exits when no connection is left, or when the drain deadline elapses (`drain_deadline`, default 30s). What is still open then, a long download or a gRPC stream, is cut.

Because GFE is stateless and the L4 LB consistent-hashes, draining one GFE node only resets the connections that were live on it; clients reconnect and land on a healthy node.

---

## 8. Configuration Model

Following `lb`, configuration is split into a **bootstrap node config** (TOML, read once at startup) and a **dynamic config** (JSON, watched and hot-reloaded). Both deserialize via `gfe-types/src/config.rs`.

### 8.1 Bootstrap node config (TOML)

```toml
# /etc/gfe/gfe.toml
# Deserialized by gfe-types/src/config.rs (NodeConfig)

[node]
id              = "gfe-node-01"
loopback_vip    = "188.184.100.10"     # service VIP on loopback (DSR); see Section 11
metrics_addr    = "127.0.0.1:9101"     # /healthz, /readyz, /metrics
worker_threads  = 0                     # 0 = Tokio default (= num CPUs)

[control_plane]
config_file     = "/etc/gfe/gfe-dynamic.json"   # listeners/routes/pools/certs, watched via inotify
local_cache     = "/var/lib/gfe/config-cache.json"
reload_debounce = "250ms"

[tls]
min_version     = "1.2"                 # "1.2" or "1.3"
hsts            = "max-age=31536000; includeSubDomains"
ticket_key_file = "/etc/gfe/tls-ticket-keys"    # shared across fleet for cross-node resumption (optional)

[limits]
max_connections          = 100000       # global concurrent client connections
max_connections_listener = 50000        # per listener
max_header_bytes         = 65536
max_h2_concurrent_streams = 256
max_upstream_connections = 20000        # global, across all pools

[timeouts]
tls_handshake     = "10s"
request_header    = "10s"
upstream_connect  = "3s"
upstream_first_byte = "30s"
request_total     = "60s"
client_idle       = "75s"
drain_deadline    = "30s"

[health_check_defaults]
interval             = "5s"
timeout              = "2s"
healthy_threshold    = 2
unhealthy_threshold  = 3
path                 = "/healthz"
```

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

> **Why JSON for the dynamic part and TOML for the bootstrap part?** This mirrors `lb` exactly: the bootstrap config is small, hand-edited, and node-specific (TOML reads well by hand); the dynamic config is fleet-wide, machine-generated by deployment tooling, and reloaded constantly (JSON is the universal generation target). Keeping them separate also means a bad dynamic reload never touches the node's identity/bind settings.

---

## 9. TLS Policy

A single, centrally enforced policy applies to every HTTPS listener:

- **Minimum protocol version:** TLS 1.2 (default) or TLS 1.3-only (configurable). SSLv3/TLS 1.0/1.1 are never offered.
- **Cipher suites / signature schemes:** a curated modern set (AEAD only; forward secrecy required). rustls's safe defaults are the baseline; the policy may further restrict.
- **ALPN:** advertises `h2` then `http/1.1`.
- **HSTS:** injected on all HTTPS responses per `[tls].hsts`.
- **Session resumption:** TLS 1.3 PSK / TLS 1.2 tickets, using fleet-shared ticket keys for cross-node resumption (Section 6.2).
- **SNI required (configurable):** connections without SNI are served the default certificate, or rejected if no default is configured.
- **mTLS from clients:** out of scope for the MVP (the public edge does not require client certs); the upstream leg may use mTLS (Section 6.6).

Centralizing this is the point: teams get correct, uniform, audited TLS with zero per-team configuration.

---

## 10. Upstream Requirements

Application backends behind GFE are ordinary HTTP servers. Unlike the L4 LB's backends, they do **not** need GRE tunnels or loopback VIPs, because GFE is a full proxy on the upstream leg (a normal client connection from the GFE node's IP to the backend's IP). Requirements are minimal:

- **Reachability:** the backend's IP is routable from GFE nodes (guaranteed by the organization's globally-routable IP service domains).
- **A health endpoint:** an HTTP(S) path returning 2xx when ready (default `/healthz`). To use lame-duck draining, it returns the configured drain signal when the backend wants to stop receiving new requests.
- **Real client IP awareness:** backends read the original client IP from `X-Forwarded-For` / `Forwarded` rather than the socket peer (which is the GFE node).
- **(Optional) Upstream TLS:** if `scheme=https`, the backend presents a certificate GFE can validate (system roots or a pinned CA); for mTLS, it requires GFE's client certificate.

A reference onboarding script (`deploy/backend-onboard.sh`) and docs help teams expose a conformant health endpoint and read forwarding headers.

---

## 11. L4 Load Balancer Integration

GFE is registered as a **backend pool in the `lb` L4 load balancer**. The L4 LB owns spreading client connections across GFE nodes; GFE owns everything from TLS up.

**How packets reach a GFE node.** The L4 LB Maglev-selects a GFE node per flow and **GRE-encapsulates** the client packet to it (`lb` Section 6.6). Therefore each GFE node must satisfy `lb`'s backend requirements (`lb` Section 10):

- **GRE tunnel interface** that decapsulates packets from L4 LB nodes:
  ```bash
  ip tunnel add gre-lb mode gre local <gfe_node_ip> ttl 64
  ip link set gre-lb up
  ```
- **Service VIP on loopback** (ARP suppressed) so the decapsulated packet, addressed to the VIP, is accepted by the local kernel and delivered to GFE's listening socket:
  ```bash
  ip addr add <vip>/32 dev lo
  sysctl -w net.ipv4.conf.all.arp_ignore=1
  sysctl -w net.ipv4.conf.all.arp_announce=2
  ```

**Return path (DSR).** Because the VIP is on the GFE's loopback and GFE is the TCP/TLS endpoint, GFE sends responses **directly to the client with source IP = VIP**. The L4 LB is never on the return path — Direct Server Return, exactly as `lb`'s design intends for its backends. The upstream leg (GFE → application backend) is a separate, ordinary connection and is unaffected.

**Health interplay.** The L4 LB health-checks the GFE pool (typically a TCP or HTTPS probe to the VIP). GFE's own `/readyz` is what the L4 LB should probe so that a draining or unhealthy GFE node is withdrawn from the L4 Maglev set (Section 7.4). GFE independently health-checks the application backends at L7. The two health layers are complementary and independent.

**Division of responsibility.**

| Concern | `lb` (L4) | GFE (L7, this project) |
|---|---|---|
| Spread traffic across GFE nodes | ✅ Maglev + ECMP | — |
| Survive node loss without coordination | ✅ consistent hash | ✅ stateless nodes |
| TLS termination & certs | — | ✅ |
| HTTP routing (host/path) | — | ✅ |
| Upstream LB & pooling | — | ✅ |
| L7 health checks | — (L4 connectivity only) | ✅ |
| BGP / packet forwarding | ✅ | — |

---

## 12. Observability

> **Code location:** `crates/gfe-metrics/` (registration) + `crates/gfe-trace/` (diagnostics)

### 12.1 Metrics

Each GFE node exposes Prometheus metrics at `http://<node>:9101/metrics`.

**Proxy / data-plane metrics (`proxy_metrics.rs`):**

| Metric | Type | Description |
|---|---|---|
| `gfe_connections_accepted_total` | Counter | Client connections accepted (labels: listener) |
| `gfe_connections_active` | Gauge | Currently open client connections |
| `gfe_listener_connections_active` | Gauge | Currently open client connections (label: listener) |
| `gfe_connections_rejected_total` | Counter | Connections rejected (label: reason ∈ {limit, handshake_timeout}) |
| `gfe_connections_closed_total` | Counter | Closed connections (labels: listener, reason ∈ {closed, client_abort, idle_timeout, header_timeout, drain, protocol_error, tls_handshake_failed, tls_handshake_timeout, error, shutdown}) |
| `gfe_connection_duration_seconds` | Histogram | Lifetime of client connections (label: listener) |
| `gfe_bytes_in_total` / `gfe_bytes_out_total` | Counter | Bytes read from / written to client sockets, on the wire (TLS included), counted as they flow (label: listener) |
| `gfe_tls_handshakes_total` | Counter | TLS handshakes (label: result ∈ {ok, failed}) |
| `gfe_tls_handshake_failures_total` | Counter | Failed handshakes (label: reason ∈ {invalid_message, peer_incompatible, alert_received, peer_misbehaved, client_closed, io_error, other}) |
| `gfe_tls_connections_total` | Counter | TLS connections established (labels: version, cipher, alpn, resumed) |
| `gfe_tls_handshake_duration_seconds` | Histogram | Handshake latency |
| `gfe_tls_sni_no_cert_total` | Counter | Handshakes with no matching certificate |
| `gfe_requests_total` | Counter | Finished requests (labels: listener, host, route, status). `host` is the matched route's configured pattern, never the raw `Host`. Status `499` = abandoned by the client before GFE had a response |
| `gfe_requests_in_flight` | Gauge | Requests received whose response is not finished yet |
| `gfe_requests_aborted_total` | Counter | Requests broken off before completion (labels: listener, host, route, by ∈ {client, upstream}) |
| `gfe_request_duration_seconds` | Histogram | Time from the request head to the last byte of the response (labels: listener, host, route) |
| `gfe_request_body_bytes_total` / `gfe_response_body_bytes_total` | Counter | Body bytes received from / sent to clients (labels: listener, host, route) |
| `gfe_grpc_responses_total` | Counter | Finished gRPC calls (labels: listener, host, route, grpc_status = the numeric gRPC status code, 0 is OK) |
| `gfe_no_route_total` | Counter | Requests matching no route (404) |
| `gfe_no_healthy_upstream_total` | Counter | Requests with no healthy upstream (503) |
| `gfe_upstream_requests_total` | Counter | Upstream requests (labels: pool, backend, status) |
| `gfe_upstream_request_duration_seconds` | Histogram | Upstream round-trip latency |
| `gfe_upstream_errors_total` | Counter | Upstream requests that failed before any response (labels: pool, backend, kind ∈ {connect_timeout, connect_refused, connect_error, tls, reset, connection_limit, timeout, other}) |
| `gfe_upstream_connect_errors_total` | Counter | The same, all kinds together (kept for existing dashboards) |
| `gfe_upstream_retries_total` | Counter | Requests retried against a new backend selection (label: pool) |
| `gfe_upstream_requests_in_flight` | Gauge | Requests a backend is working on, until the response has been relayed to its end (labels: pool, backend) |
| `gfe_upstream_connections` / `gfe_upstream_connections_limit` | Gauge | Upstream connections open over all backends, and the configured `max_upstream_connections` |

**Control-plane metrics (`control_metrics.rs`):**

| Metric | Type | Description |
|---|---|---|
| `gfe_backend_health_status` | Gauge | 1=HEALTHY, 0=UNHEALTHY (labels: pool, backend); DRAINING exposed separately |
| `gfe_backend_draining` | Gauge | 1 if backend is in lame-duck DRAINING (labels: pool, backend) |
| `gfe_health_check_duration_seconds` | Histogram | Probe round-trip time |
| `gfe_config_last_reload_timestamp` | Gauge | Unix time of last successful dynamic-config reload |
| `gfe_config_reload_errors_total` | Counter | Failed reloads (kept old snapshot) |
| `gfe_config_from_cache` | Gauge | 1 while the node serves its last-known-good cache because the deployed dynamic config was unusable at startup |
| `gfe_cert_expiry_timestamp` | Gauge | not-after Unix time (label: sni) — alert before expiry |
| `gfe_active_routes` / `gfe_active_pools` | Gauge | Sizes of the current snapshot |

**Saturation (`process_metrics.rs`, `proxy_metrics.rs`):**

| Metric | Type | Description |
|---|---|---|
| `gfe_connections_limit` / `gfe_listener_connections_limit` | Gauge | The configured `max_connections` / `max_connections_listener`, so connection saturation is `gfe_connections_active / gfe_connections_limit` |
| `process_open_fds` / `process_max_fds` | Gauge | Open file descriptors and their limit (Linux). Running out of descriptors is how a proxy usually fails first |
| `process_resident_memory_bytes` | Gauge | Resident memory (Linux) |
| `process_cpu_seconds_total` | Counter | User + system CPU time (Linux); `rate()` of it is cores in use |
| `process_start_time_seconds` | Gauge | Process start, Unix seconds (restarts show as a step) |
| `gfe_runtime_workers` / `gfe_runtime_alive_tasks` / `gfe_runtime_global_queue_depth` | Gauge | Async runtime: worker threads, live tasks, and tasks queued for a free worker — the last one rising means the workers are saturated |
| `gfe_build_info` | Gauge | Always 1 (label: version) |

The `process_*` names are the ones every Prometheus client library uses, so stock dashboards and alerts apply unchanged.

**Kernel view (`gfe-ebpf`, `kernel_metrics.rs`) — optional, `[ebpf] enabled = true`:**

Some facts about a connection exist only in the kernel. With the eBPF program attached, the node reports them; without it, these series stay empty and nothing else changes.

| Metric | Type | Description |
|---|---|---|
| `gfe_ebpf_attached` | Gauge | 1 while the kernel program is attached |
| `gfe_ebpf_lost_events` | Gauge | Closed connections the kernel could not report because the reader fell behind |
| `gfe_accept_queue_wait_seconds` | Histogram | Time a connection spent established but not yet accepted (label: listener). The earliest sign of a node falling behind |
| `gfe_client_tcp_rtt_seconds` | Histogram | Smoothed round-trip time to the client when its connection closed (label: listener) |
| `gfe_client_tcp_segments_sent_total` / `gfe_client_tcp_retransmits_total` | Counter | Segments sent / retransmitted to clients on closed connections (label: listener); their ratio is the loss clients experience |
| `gfe_client_tcp_closes_total` | Counter | Closed client connections (labels: listener, ending ∈ {peer_closed, node_closed, aborted, other}) |
| `gfe_upstream_tcp_rtt_seconds` | Histogram | The same for connections to backends (label: backend = `ip:port` as the kernel sees it): network distance to a backend, separate from how fast it answers |
| `gfe_upstream_tcp_segments_sent_total` / `gfe_upstream_tcp_retransmits_total` | Counter | (label: backend) |
| `gfe_upstream_tcp_closes_total` | Counter | (labels: backend, ending) |

How it works, and what it does not assume:

- One `sockops` program is attached to the **cgroup the node runs in**, so it sees exactly the node's sockets: connections it accepts and connections it opens (traffic to backends and health probes alike). It observes **sockets, not packets**, and is therefore indifferent to how traffic reached the node: through the L4 LB and its GRE tunnel, or directly from clients behind a DNS load balancer.
- `ending` is read from the TCP state a connection was closed from: who sent its FIN first (`peer_closed`, `node_closed`), or no orderly shutdown at all (`aborted`: a reset in either direction, or the kernel giving up on a silent peer). On TLS connections the node usually closes first, in answer to the client's `close_notify`.
- Statistics are reported once per connection, when it closes. A long-lived connection contributes when it ends.
- Requirements: Linux ≥ 5.8, a build made with clang available, and `CAP_BPF` + `CAP_NET_ADMIN` (drop-in: `deploy/gfe-node-ebpf.conf`). The kernel program is C, checked by the kernel's verifier before it runs; the Rust side has no `unsafe`. Where any requirement is missing the node logs the reason and runs without the kernel view.

### 12.2 Request Tracer

> **Code location:** `crates/gfe-trace/`

A diagnostic CLI that issues a marked request and reports the routing decision without affecting production:

```
gfe-trace --host atlas.example.org --path /api/v1/users --method GET
```

It prints which listener/route matched, which pool and which backend would be selected (under the pool's LB policy), the upstream scheme, and whether a pooled connection would be reused. Essential for debugging misrouted requests.

### 12.3 Logging

- **Structured JSON logs** via `tracing` + `tracing-subscriber`.
- **Access logs** (`record.rs`): one structured event per request under the target `gfe::access`, emitted when the exchange is **over** — the response written to its last byte, or abandoned — so sizes, duration and outcome are final. A request the client gives up on before any response is still logged. Fields:

  | Field | Meaning |
  |---|---|
  | `request_id` | Client-supplied `X-Request-Id` if valid, else generated; also sent upstream and returned on synthetic responses |
  | `client`, `client_port` | Peer address of the connection |
  | `listener`, `proto`, `http_version`, `sni` | Where and how the request arrived |
  | `method`, `host`, `path`, `user_agent` | The request (no query string, no other headers) |
  | `status` | Response status; `499` when the client left before a response existed |
  | `grpc_status` | For gRPC calls (`content-type: application/grpc*`), the numeric status the call ended with, read from the response trailers (or headers, for calls that fail before any message). A gRPC call is HTTP `200` whatever its outcome, so this is the field that tells success from failure |
  | `route`, `pool`, `backend`, `attempts` | Routing decision, the backend of the last attempt, and how many attempts were made |
  | `error` | Why GFE answered itself: `no_route`, `pool_not_found`, `no_healthy_upstream`, `upstream_connect_timeout`, `upstream_connect_refused`, `upstream_connect_error`, `upstream_tls`, `upstream_reset`, `upstream_connection_limit`, `upstream_error`, `upstream_timeout`, `request_body_timeout` (a `408`: the client stalled while sending the body), `unknown_acme_challenge` |
  | `termination` | `complete`, `client_abort` (client left before or during the response) or `upstream_abort` (upstream failed mid-body) |
  | `request_bytes`, `response_bytes` | Body bytes actually read from / written to the client |
  | `duration_ms` | Request head to last response byte, microsecond resolution |
  | `upstream_ttfb_ms` | First upstream attempt to upstream response headers |

  | `tls_version`, `tls_cipher` | Negotiated TLS parameters of the connection the request arrived on |

  Fields that do not apply to a request are omitted.
- **Connection logs** (`conn_record.rs`): one structured event per client connection under the target `gfe::conn`, emitted when the connection is gone. Fields: `client`, `client_port`, `listener`, `proto`, `sni`, `tls_version`, `tls_cipher`, `alpn`, `tls_resumed`, `tls_handshake_ms`, `tls_error` (why a handshake failed), `accept_wait_ms` (time in the accept queue; only with the kernel view), `requests` (served on the connection), `bytes_in` / `bytes_out` (on the wire), `duration_ms`, `reason` (as in `gfe_connections_closed_total`) and `error` (the error text, when there was one). Both targets can be silenced or routed independently, e.g. `RUST_LOG=info,gfe::conn=off`.
- **TCP logs** (`gfe-node/src/kernel.rs`, only with the kernel view): one event per closed TCP connection under the target `gfe::tcp`. Fields: `side` (`client` or `upstream`), `client` and `client_port` (the same as in the `gfe::conn` event of that connection) or `backend`, `listener`, `ending`, `rtt_ms`, `min_rtt_ms`, `retransmits`, `segments_sent`, `bytes_acked`, `bytes_received`, `lifetime_ms`.
- Log levels: ERROR/WARN always on; INFO/DEBUG adjustable at runtime via an env-filter reload, no restart.
- **No body logging.** Headers are logged selectively (allowlist) to avoid leaking secrets.

### 12.4 Health Endpoints

Served on the metrics address:

```
GET /healthz   → 200 if the proxy is running
GET /readyz    → 200 if at least one listener is bound and a valid config is loaded;
                 503 while draining — this is what the L4 LB should probe
GET /metrics   → Prometheus exposition
```

---

## 13. Failure Modes and Resilience

### GFE Node Failure

- The L4 LB detects the failed GFE node via its health probe and removes it from the Maglev set within the probe's failure window. Remaining GFE nodes absorb the traffic; the L4 consistent hash redistributes new flows with no coordination.
- **Connection impact:** flows that were live on the failed node reset; clients reconnect and land on a healthy node. GFE statelessness makes any node a valid replacement.
- **Capacity:** size the GFE fleet with N+1 headroom so any N−1 nodes carry full load.

### Upstream Failure

- The L7 health checker detects it within `interval × unhealthy_threshold` (default 15s) and removes it from the pool's healthy set; idle connections to it are dropped.
- In-flight requests to a backend that fails mid-response cannot be safely retried (bytes already sent) and surface as 502; pre-response failures on idempotent requests are retried within budget (Section 6.8).
- If a pool has no healthy upstreams, requests get 503; the route still exists, so recovery is automatic when a backend returns.

### Config / Cert Source Unreachable

- The dynamic config and certs are local files; GFE never makes a runtime call to fetch them. If the deployment tooling cannot push an update, GFE keeps serving the last-loaded (and locally cached) config indefinitely.
- A malformed reload is rejected wholesale; the running snapshot is retained and `gfe_config_reload_errors_total` increments.
- A node restarted while its dynamic config is missing or broken starts from the last-known-good cache (Section 7.2) and sets `gfe_config_from_cache`.

### Certificate Expiry

- `gfe_cert_expiry_timestamp{sni}` drives proactive alerting. With ACME (Phase 3), renewal is automatic; without it, monitoring + deployment tooling handle rotation. An expired cert is still served (so the failure mode is a visible TLS warning, not a hard outage) but alerts fire well before.

### Overload

- Connection and stream limits bound resource use; excess connections are refused cleanly rather than driving the node into memory pressure. Upstream connection caps protect backends from connection storms during failover.
- The proxy applies backpressure naturally: slow clients or upstreams throttle their own streams without starving others (per-connection, async).

### Reload Under Load

- Route table and cert store swaps are atomic `ArcSwap` pointer updates; in-flight requests complete on the old snapshot. There is no stop-the-world, no dropped connections, and no lock contention on the hot path.

---

## 14. Operational Considerations

### Rolling Restarts and Upgrades

1. Drain the node (`SIGTERM` or operator command): `/readyz` flips to 503, the L4 LB withdraws it from the Maglev set within its probe window.
2. The node stops accepting new connections and serves in-flight requests until they finish or the drain deadline elapses.
3. Restart the `gfe-node` binary; it loads config (or cache), binds listeners, passes `/readyz`, and the L4 LB re-adds it.

Statelessness means a restarted node is immediately a full peer — no warmup state to rebuild beyond connection pools, which refill on demand.

### Adding a GFE Node

1. Provision the node, configure the GRE tunnel and loopback VIP (Section 11), install the config file.
2. Start the service; it passes `/readyz`; register it in the L4 LB's GFE pool.
3. Capacity increases immediately; existing connections on other nodes are unaffected.

### Adding / Changing a Route, Pool, or Certificate

1. Deployment tooling writes the updated dynamic-config JSON (and any cert files) to each GFE node. It should gate the write on `gfe-node --check-config --dynamic-config <candidate>`, which validates the candidate file exactly as the node would before it replaces the deployed one (e.g. as a Puppet `validate_cmd`); adding `--config <toml>` checks the bootstrap config in the same run.
2. The inotify watcher fires; the config manager validates and atomically swaps the snapshot within the debounce window.
3. New requests use the new routing/certs immediately; in-flight requests finish on the old snapshot. No restart, no dropped connections.

### Rotating Certificates

- Write the new cert/key files in place (and update the dynamic config if the path/SNI set changed). The certificate poller notices within 10 s, reloads, and swaps the cert store atomically — no config change or restart needed. With shared TLS ticket keys, resumption continues to work across the rotation.

### Capacity Planning

- The dominant costs at the GFE tier are **TLS handshakes/sec** (CPU) and **concurrent connections** (memory + FDs), not raw bandwidth. Size for handshake rate and connection count; connection pooling keeps upstream connection counts far below client connection counts.

---

## 15. Implementation Roadmap

> Status legend: **[x]** implemented & tested, **[~]** partial (see note).

### Phase 1 — Core Proxy (MVP) ✅

- [x] `gfe-types`: domain types (Listener, Route, UpstreamPool, Upstream, TlsConfig, CertEntry) + bootstrap & dynamic config structs
- [x] `gfe-tls`: cert store, SNI resolver, TLS policy / `ServerConfig` builder, PEM loader
- [x] `gfe-router`: compiled route table, host (exact + wildcard) and path (prefix/exact) matching
- [x] `gfe-upstream`: pool handle, round-robin policy, hyper upstream client, connection pooling
- [x] `gfe-proxy`: acceptor, per-connection TLS + HTTP serve, routing, forwarding, synthetic errors
- [x] `gfe-metrics`: proxy metrics + Prometheus endpoint
- [x] `gfe-config`: loader + validator + applier (atomic swap) for the dynamic config
- [x] `gfe-node`: binary wiring proxy + config from local file; `--check-config`
- [x] Integration tests (TLS termination, routing, proxying) against mock upstreams
- [x] `config/gfe.example.toml`

### Phase 2 — Control Plane and Resilience ✅

- [x] `gfe-health`: HTTP/HTTPS/TCP probes, dedup, state machine, shared health map
- [x] `gfe-config`: inotify watcher + debounce + last-known-good cache
- [x] `gfe-controller`: orchestrator wiring config + health + cert lifecycle
- [x] `gfe-upstream`: `least_request` and `ring_hash` (affinity) policies, upstream TLS validation
- [x] bounded pools — idle connections bounded per host; open upstream connections capped node-wide (`max_upstream_connections`)
- [x] `gfe-proxy`: graceful drain (deadline), request-total timeout, conservative idempotent retries, connection limits
- [x] per-stage timeouts — TLS handshake, request header, client idle, upstream connect, upstream first-byte and overall `request_total`
- [x] `gfe-metrics`: control-plane metrics; structured access logging (`gfe::access`)
- [x] `gfe-trace` CLI (offline routing tracer)

### Phase 3 — Completeness and Operations ✅

- [x] Lame-duck drain protocol for upstreams (DRAINING state, drain-status detection)
- [x] mTLS to upstreams (client certificate) + extra-CA trust
- [x] `deploy/`: systemd unit, GRE+VIP onboarding script, config generate/validate scripts, Grafana dashboard
- [~] ACME `http-01` — challenge store + `/.well-known/acme-challenge/` serving implemented & tested; the CA-ordering driver (e.g. `instant-acme`) is a documented integration point (requires a live ACME endpoint to exercise). `tls-alpn-01` deferred.
- [~] TLS session resumption — per-node rotating ticketer enabled; fleet-shared ticket keys from file is a documented follow-up
- [ ] Load and soak testing framework in `tests/` (deferred)

### Phase 4 — Optional Enhancements (explicitly deferred)

- [ ] HTTP/3 (QUIC) downstream
- [ ] Edge rate limiting / basic DoS hygiene
- [ ] Response caching layer
- [ ] Request/response header transformation rules

---

## 16. Technology Stack

| Component | Technology | Crate(s) | Rationale |
|---|---|---|---|
| Language | Rust | all | Memory safety without GC pauses; strong async ecosystem; matches `lb` |
| Async runtime | `tokio` | proxy + control plane | The natural model for an L7 proxy |
| HTTP server + client | `hyper` 1.x + `hyper-util` | `gfe-proxy`, `gfe-upstream` | h1/h2 server and client, streaming bodies, battle-tested |
| HTTP types / bodies | `http`, `http-body-util` | `gfe-proxy`, `gfe-upstream` | Shared request/response and streaming-body abstractions |
| TLS | `rustls` + `tokio-rustls` | `gfe-tls` | Safe, modern TLS; pluggable `ResolvesServerCert` for SNI |
| Cert parsing | `rustls-pemfile`, `x509-parser` | `gfe-tls` | PEM loading and not-after extraction |
| Upstream trust roots | `rustls-native-certs` / `webpki-roots` | `gfe-upstream` | Validate upstream TLS |
| ACME (Phase 3) | `instant-acme` | `gfe-tls` | Async, rustls-native certificate automation |
| Config serialization | `serde` + `toml` + `serde_json` | `gfe-types`, `gfe-config` | TOML bootstrap, JSON dynamic config (mirrors `lb`) |
| File watching | `notify` | `gfe-config` | inotify-based hot reload (ADR-001) |
| Atomic config swap | `arc-swap` | `gfe-router`, `gfe-tls`, `gfe-config` | Lock-free snapshot reads on the hot path |
| Shared health map | `dashmap` | `gfe-health` | Concurrent reads from the data plane |
| Metrics | `prometheus-client` | `gfe-metrics` | Direct Prometheus exposition (same as `lb`) |
| Logging / tracing | `tracing` + `tracing-subscriber` | all | Structured, async-aware, runtime-adjustable levels |
| CLI | `clap` | `gfe-node`, `gfe-trace` | Arg parsing (same as `lb`) |
| Error handling | `thiserror`, `anyhow` | all | Library vs. binary error idioms (same as `lb`) |
| Testing | `cargo test` + mock upstreams | `tests/` | Socket-level integration without physical backends |
| Benchmarks | `criterion` | `tests/benchmarks/` | Routing and handshake micro-benchmarks |

---

*Document version: 0.1 — Initial specification.*
*Companion to: the `lb` Maglev L4 load balancer (Section 11, "Frontend (GFE) Integration").*
*Based on: Google's Front End service (Google infrastructure security design; Maglev, Eisenbud et al., NSDI 2016).*
</content>
</invoke>
