# GFE Control Plane — Configuration Management & Deployment Specification v0.1

> A declarative control plane that holds the desired state of every GFE fleet in
> a single database, renders the node-facing configuration, and reconciles it
> onto the running nodes via a per-node pull agent.

This document specifies **only** the configuration and deployment system. The GFE
data plane (`thewillyhuman/gfe`) and the `lb` L4 layer are treated as fixed
contracts that this system must produce valid input for.

---

## 1. Context and scope

A GFE node reads two configuration layers (`gfe-types::config`):

| Layer | File | How the node consumes it | Scope |
|---|---|---|---|
| **Static** | bootstrap `gfe.toml` (`NodeConfig`) | read **once at startup** | per-node identity + fleet policy |
| **Dynamic** | `gfe-dynamic.json` (`DynamicConfig`) | **hot-reloaded** via inotify, atomic `ArcSwap` | fleet-global |

The single most important property: **the dynamic JSON is identical across every
node in a fleet.** All nodes hold the same service VIP on loopback (DSR) and bind
the same listeners, so there is exactly one logical dynamic document per fleet,
fanned out to N interchangeable nodes. Only the static TOML carries a small
per-node overlay (chiefly `node.id`).

The control plane therefore reduces to: *maintain desired state in a DB → render
one dynamic JSON (+ per-node TOML) per fleet → distribute and confirm.*

### 1.1 In scope

- A normalized **database** of desired state: fleets, nodes, listeners,
  certificates, pools, backends, routes.
- A **render engine** that produces `DynamicConfig` JSON and per-node `NodeConfig`
  TOML byte-for-byte acceptable to the node.
- **Validation** identical to the node's own (`gfe-config::validate`).
- Immutable, content-addressed **revisions** with rollback.
- A per-node **pull agent** (`gfe-agent`) that fetches, materializes certs,
  atomically swaps the dynamic file, and reports applied state.
- **Rollout orchestration** (canary → waves) and **rollback**.
- An **API + CLI + SDK** for declarative changes and backend registration.

### 1.2 Out of scope

- The GFE data plane and the `lb` L4 layer.
- Certificate *issuance* / ACME ordering. The control plane **stores and serves**
  cert material; obtaining it (CERN cert-manager, Let's Encrypt) is upstream.
- Metrics/alerting dashboards beyond what rollout confirmation needs.
- Host provisioning (that is `cernetes`' job).

---

## 2. Components

```
                         ┌───────────────────────────────┐
   operators / CI ──────▶│  gfectl (CLI) / SDK / REST     │
                         └───────────────┬───────────────┘
                                         │ gRPC
                         ┌───────────────▼───────────────┐
                         │          gfe-cp                │
                         │  ┌──────────┐  ┌────────────┐  │
                         │  │  API     │  │  Renderer  │  │   links gfe-types
                         │  ├──────────┤  ├────────────┤  │   + gfe-config
                         │  │ Revision │  │ Validator  │◀─┼── (same code as node)
                         │  │  store   │  ├────────────┤  │
                         │  ├──────────┤  │  Rollout   │  │
                         │  │ Node reg │  │ orchestr.  │  │
                         │  └──────────┘  └────────────┘  │
                         └───────┬───────────────┬────────┘
                                 │ Postgres      │ agent API (mTLS, long-poll)
                         ┌───────▼──────┐        │
                         │  PostgreSQL  │        │
                         │ desired state│        │
                         │ + cert blobs │        │
                         │ + revisions  │        │
                         └──────────────┘        │
                                                 ▼
              ┌───────────── fleet: atlas-prod ──────────────┐
              │   gfe-node-01        gfe-node-02   ...  -N    │
              │   ▲  gfe-agent       ▲  gfe-agent             │
              │   │  writes certs    │                        │
              │   │  + dynamic.json  │  (identical per node)  │
              └───┼──────────────────┼────────────────────────┘
                  │ atomic rename     │ inotify → ArcSwap reload
```

- **`gfe-cp`** — the controller. Stateless service; all state in Postgres. Serves
  the operator API and the agent API.
- **`gfectl` / SDK** — thin clients over the gRPC API (mirrors `cernetes`).
- **`gfe-agent`** — runs on every GFE node next to `gfe-node`. **Pull** model.

---

## 3. Data model

PostgreSQL. Every table is desired state; the node-facing files are *derived* and
never authored directly. Types map 1:1 onto `gfe-types`.

### 3.1 Fleets (config groups / shards)

A fleet is a set of interchangeable nodes that share one dynamic config and one
policy block. Modeled as first-class from day one so sharding needs no migration.

```
fleet
  id              UUID PK
  name            TEXT UNIQUE         -- "atlas-prod"
  vip             INET                -- service VIP held on each node's loopback
  -- fleet-wide static policy (→ TOML [tls]/[limits]/[timeouts]/[upstream]/[health_check_defaults])
  tls_min_version TEXT  DEFAULT '1.2' -- '1.2' | '1.3'
  hsts            TEXT  DEFAULT ''
  ticket_key_ref  UUID  NULL          -- → secret holding fleet-shared ticket keys
  limits          JSONB               -- max_connections, max_header_bytes, ...
  timeouts        JSONB               -- tls_handshake, upstream_connect, ...
  upstream_opts   JSONB               -- idle_per_host, client_cert_ref, extra_ca_ref
  health_defaults JSONB               -- type, interval, thresholds, path, ...
  rollout_policy  JSONB               -- canary size, wave %, bake time (see §8)
  created_at, updated_at
```

### 3.2 Nodes (frontend replicas)

```
node
  id              UUID PK
  fleet_id        UUID FK → fleet
  gfe_node_id     TEXT                -- → TOML node.id (unique within fleet)
  mgmt_addr       INET                -- agent reachability / inventory
  metrics_addr    TEXT                -- → TOML node.metrics_addr (default 127.0.0.1:9101)
  worker_threads  INT  DEFAULT 0
  enabled         BOOL DEFAULT true
  -- observed state (written by the agent, §7)
  applied_revision BIGINT NULL
  last_seen        TIMESTAMPTZ
  reload_state     TEXT               -- OK | FAILED | PENDING
  UNIQUE (fleet_id, gfe_node_id)
```

### 3.3 Listeners → `listeners[]`

```
listener
  id        UUID PK
  fleet_id  UUID FK
  name      TEXT       -- → Listener.id  ("https", "http")
  address   INET       -- → Listener.address (usually = fleet.vip)
  port      INT        -- → Listener.port
  protocol  TEXT       -- 'http' | 'https'
  UNIQUE (fleet_id, name)
```

### 3.4 Certificates → `certificates[]`  (PEMs stored in DB)

```
certificate
  id          UUID PK
  fleet_id    UUID FK
  is_default  BOOL DEFAULT false        -- at most one per fleet (enforced, §6)
  cert_pem    BYTEA                     -- full chain, ENCRYPTED at rest (§9)
  key_pem     BYTEA                     -- private key, ENCRYPTED at rest (§9)
  content_sha TEXT                      -- sha256(cert||key); drives on-node path
  not_after   TIMESTAMPTZ              -- for expiry alerting
  created_at

certificate_sni                         -- → CertEntry.sni[]
  certificate_id UUID FK
  sni            TEXT                    -- exact or "*.single-label" wildcard
  PRIMARY KEY (certificate_id, sni)
```

The rendered `cert_file` / `key_file` paths are **content-addressed and
controller-generated**, never user-supplied:
`/etc/gfe/certs/<content_sha>.crt.pem` and `.key.pem`. Immutable paths mean
rotation is "add a new cert row, point a binding at it" — never an in-place
overwrite, so a reload can never observe a torn cert/key pair.

### 3.5 Pools → `pools[]` and backends → `upstreams[]`

```
pool
  id            UUID PK
  fleet_id      UUID FK
  name          TEXT      -- → UpstreamPool.id
  scheme        TEXT DEFAULT 'http'        -- 'http' | 'https'
  lb_policy     TEXT DEFAULT 'round_robin' -- round_robin | least_request | ring_hash
  health_check  JSONB NULL                 -- per-pool override; NULL = fleet defaults
  UNIQUE (fleet_id, name)

backend                                    -- the churny table: service onboard/offboard
  id        UUID PK
  pool_id   UUID FK
  host      TEXT
  port      INT
  weight    INT DEFAULT 1
  enabled   BOOL DEFAULT true              -- disabled rows are omitted from render
  UNIQUE (pool_id, host, port)
```

### 3.6 Routes → `routes[]`

```
route
  id            UUID PK
  fleet_id      UUID FK
  name          TEXT       -- → Route.id
  listener_id   UUID FK    -- → Route.listener (name resolved at render)
  host          TEXT       -- exact | "*.example.org" | "*"
  path_prefix   TEXT DEFAULT '/'
  action_kind   TEXT       -- 'forward' | 'redirect' | 'fixed'
  forward_pool  UUID FK NULL   -- when forward
  redirect      JSONB NULL     -- {scheme, status}        when redirect
  fixed         JSONB NULL     -- {status, body}          when fixed
  UNIQUE (fleet_id, name)
```

### 3.7 Revisions

```
revision
  id           BIGSERIAL PK
  fleet_id     UUID FK
  seq          BIGINT              -- monotonic per fleet
  dynamic_json BYTEA               -- the exact rendered DynamicConfig
  cert_set     JSONB               -- [{path, content_sha}] referenced by this rev
  static_tmpl  BYTEA               -- fleet portion of the TOML (node id injected per node)
  content_hash TEXT                -- hash over the above; the rollout target id
  created_by   TEXT
  created_at
  UNIQUE (fleet_id, seq)
```

A revision is **immutable**. Any desired-state change that alters the render
produces a new revision; rollback selects an older `seq`.

---

## 4. Rendering

The renderer is a pure function `desired_state(fleet) → (DynamicConfig, NodeConfig templates)`.
It depends on the real `gfe-types` crate so the structs it serializes are exactly
the ones the node deserializes (and `serde(deny_unknown_fields)` guarantees no
stray keys slip through).

### 4.1 Dynamic JSON field mapping

| DB | `DynamicConfig` field | Notes |
|---|---|---|
| `certificate (+ sni)` | `certificates[]` | path = `/etc/gfe/certs/<sha>.{crt,key}.pem` |
| `listener` | `listeners[]` | `name→id`, `address`, `port`, `protocol` |
| `route` | `routes[]` | `listener_id` resolved to listener **name**; action mapped |
| `pool (+ backend)` | `pools[]` | only `enabled` backends; `health_check` omitted when NULL |

Ordering is **deterministic** (sort by name) so identical desired state always
renders byte-identical JSON — stable hashes, clean diffs.

### 4.2 Static TOML rendering

`NodeConfig` = fleet policy (shared) + per-node identity overlay:

| TOML | Source |
|---|---|
| `[node] id` | `node.gfe_node_id` |
| `[node] loopback_vip` | `fleet.vip` |
| `[node] metrics_addr`, `worker_threads` | `node.*` |
| `[control_plane] config_file`, `local_cache`, `reload_debounce` | controller convention |
| `[tls]`, `[limits]`, `[timeouts]`, `[upstream]`, `[health_check_defaults]` | `fleet.*` |

Static config is rendered per node but changes rarely; treat it as **cold**
(see §8.3) because the node only reads it at startup.

---

## 5. Validation

Two layers, both run **before** a revision is created:

1. **Node-identical semantic validation** — call `gfe_config::validate()`
   directly (the controller links the crate). Guarantees parity with the node:
   unique listener/pool/route ids; routes reference an existing listener; forward
   routes reference an existing pool; pools have ≥1 upstream with non-empty host
   and non-zero port; ≤1 default certificate; an HTTPS listener requires ≥1
   certificate.
2. **Controller-only checks** the node can't make:
   - every referenced `cert_file`/`key_file` resolves to a stored cert blob;
   - SNI coverage: warn if an HTTPS route's host matches no cert SNI and no
     default exists;
   - cert expiry: refuse to roll a revision whose certs are already expired;
   - optional offline routing assertions via `gfe-trace` against the rendered
     JSON (e.g. "`atlas.example.org/` must forward to `atlas-web-pool`").

A revision that fails validation is never persisted as a rollout target.

---

## 6. Certificate handling (PEMs in DB)

- **At rest:** `cert_pem`/`key_pem` are envelope-encrypted (per-row data key
  wrapped by a KMS master key). The DB never holds plaintext private keys.
- **In transit:** only over the mTLS agent channel (§7).
- **On node:** the agent writes content-addressed files (`0600`, owned by the GFE
  user) and never deletes a file a live revision references.
- **Default cert:** a partial unique index enforces at most one
  `is_default = true` per fleet, matching the node's own rule.
- **Rotation:** insert new `certificate` row → repoint binding → new revision.
  Old file lingers until no revision references it, then GC'd by the agent.

> Note: this covers **GFE-terminated** certs only. The separate requirement where
> a service owner installs their own cert on their own host (and we cannot hand
> out a wildcard private key) is *not* a GFE-terminated path and is out of scope
> here.

---

## 7. Distribution — the pull agent

`gfe-agent` runs on each node and owns the local files. The controller never
reaches into a node; it only answers the agent.

**Authentication:** mTLS, client cert per node (or bootstrap token → cert). The
agent's identity binds it to exactly one `node` row.

**Protocol (gRPC or HTTP/2 long-poll):**

1. `GetTarget(fleet, current_revision)` — long-polls; returns when a newer
   revision is published: `{ seq, content_hash, dynamic_json, certs:[{path, sha, blob}], static_template }`.
2. Agent **materializes certs first**: write each `blob` to its content-addressed
   path, `fsync`. (Cheap — content-addressed, so already-present files are skipped.)
3. Agent writes `dynamic.json` to a temp file on the same filesystem, `fsync`,
   then **atomic `rename()`** into `control_plane.config_file`. inotify sees a
   single event; the node validates + `ArcSwap`s; in-flight requests never drop.
4. Agent observes the result: poll `gfe-node`'s `/readyz` + the config-generation
   gauge on `/metrics` to confirm the swap took.
5. `ReportStatus(node, applied_seq, reload_result, health)` — controller updates
   `node.applied_revision`, `reload_state`, `last_seen`.

**Resilience:** if the controller is unreachable the agent does nothing and the
node keeps serving its current (and last-known-good cached) config. No outage of
`gfe-cp` can take down the data plane.

**Cert GC:** after a successful swap, the agent deletes cert files referenced by
no revision in its recent retained set.

---

## 8. Rollout and rollback

### 8.1 Publishing a target

Publishing makes a revision the fleet's **target**. Agents converge toward it.
The orchestrator gates *which* nodes are allowed to advance, enabling canaries.

### 8.2 Dynamic rollout (hot, no restart)

Driven by `fleet.rollout_policy`:

1. **Canary** — advance `canary_size` nodes (default 1). Agents apply, report.
2. **Bake** — wait `bake_time` and require canary nodes report `reload_state=OK`
   and stay healthy (the L4 LB keeps routing to the rest meanwhile).
3. **Waves** — advance in `wave_pct` increments, re-checking health each wave.
4. **Done** — all nodes report `applied_revision == target`.

**Auto-halt:** if a node fails to reload or drops health within the bake window,
the orchestrator stops advancing and surfaces the failing node. Operators roll
back or fix forward.

### 8.3 Static rollout (cold, needs restart)

Static config is read once at startup, so a change requires a node restart. The
agent writes the new TOML and signals "restart required"; the orchestrator
restarts nodes **one at a time**, waiting for `/readyz` and for the L4 LB to
re-add the node (graceful drain on `SIGTERM` already handles in-flight requests).
Never restart a whole fleet at once.

### 8.4 Rollback

Rollback = publish an earlier revision as the new target. Because revisions are
immutable and certs are content-addressed, this is just another file swap — no
special path. `gfectl fleet rollback atlas-prod --to <seq>`.

---

## 9. API, CLI, SDK

gRPC service with a generated REST/JSON gateway (same pattern as `cernetes`).
Auth via OAuth2 bearer (CERN SSO); `groups` claim → fleet RBAC. All mutating RPCs
return immediately and create at most one new revision.

**Operator surface (illustrative `gfectl`):**

```
gfectl fleet create atlas-prod --vip 188.184.100.10 --tls-min 1.3
gfectl listener add atlas-prod https --addr 188.184.100.10 --port 443 --https
gfectl cert add atlas-prod --sni atlas.example.org,*.atlas.example.org \
       --cert atlas.fullchain.pem --key atlas.key.pem
gfectl cert add atlas-prod --default --cert default.pem --key default.key.pem
gfectl pool add atlas-prod atlas-web-pool --scheme https --lb ring_hash
gfectl backend add atlas-prod atlas-web-pool 188.185.10.1:8443 --weight 1
gfectl route add atlas-prod atlas-web --listener https \
       --host atlas.example.org --path / --forward atlas-web-pool
gfectl fleet diff   atlas-prod          # desired vs current target (rendered JSON diff)
gfectl fleet publish atlas-prod         # validate, create revision, start rollout
gfectl fleet status atlas-prod          # per-node applied revision + reload state
gfectl fleet rollback atlas-prod --to 41
```

**Backend (de)registration** is the high-frequency path and gets first-class,
idempotent RPCs (`RegisterBackend` / `DeregisterBackend`) so service onboarding
automation can call it directly — each call renders, validates, and rolls a new
revision (debounced to coalesce bursts).

---

## 10. Security

- Private keys envelope-encrypted at rest; plaintext only in node memory and the
  `0600` on-node file.
- Agent channel mTLS; per-node identity; an agent may only fetch its own fleet.
- Operator RBAC scoped by fleet via SSO groups.
- Full audit log of every desired-state change and every published/rolled-back
  revision (who, what, when).

---

## 11. Failure modes

| Failure | Behavior |
|---|---|
| `gfe-cp` down | Nodes keep serving; agents idle; no data-plane impact. |
| DB down | API read-only/unavailable; nodes unaffected. |
| Invalid desired state | Rejected at publish (node-identical validation); no revision created. |
| Bad revision reaches a node | Node rejects on reload, keeps current snapshot; agent reports FAILED; orchestrator auto-halts. |
| Agent crash | Node keeps current config; orchestrator sees stale `last_seen`. |
| Cert file missing for a referenced path | Caught by controller validation before publish; never shipped. |
| Torn cert/key during rotation | Impossible — content-addressed immutable paths + certs-before-JSON ordering. |

---

## 12. Phasing

1. **MVP** — DB schema, renderer + `gfe-config` validation, single revision per
   fleet, agent that writes certs + atomic-swaps JSON, `gfectl` CRUD + publish,
   all-at-once rollout.
2. **Safe rollout** — revisions, canary/waves, auto-halt, rollback, `fleet diff`.
3. **Scale & ergonomics** — backend (de)register automation hooks, cert expiry
   alerting, `gfe-trace` assertions in CI, static (cold) rollout orchestration.

---

## 13. Open questions

- Backend registration: push via API only, or also a discovery source
  (Consul/DNS) the controller syncs from?
- Revision retention/GC policy (how many to keep for rollback).
- Do we want a read-only `gfe-cp` standby for HA, or rely on stateless restart +
  Postgres HA?
- Ticket-key distribution: model fleet-shared TLS ticket keys as a rotating
  secret managed here, or out-of-band?
