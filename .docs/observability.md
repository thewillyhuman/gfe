# Observing a GFE fleet

How to answer operational questions about GFE: which signal holds the answer,
where it comes from, and what GFE deliberately does not record. The exhaustive
metric and log-field reference is [section 12 of the spec](spec.md#12-observability).

## Three sources

| Source | Unit | Carries | Cardinality |
|---|---|---|---|
| **Metrics** (`/metrics`, Prometheus) | aggregates | rates, ratios, latency distributions, saturation | bounded: labels come from config, never from clients |
| **Access log** (`gfe::access`) | one event per request | who asked for what, what happened, how long, how big | unbounded: client IPs, paths, user agents, request ids |
| **Connection log** (`gfe::conn`) | one event per connection | how clients reach the node: TLS, bytes on the wire, why connections end | unbounded |

Metrics tell you *that* something is wrong and where; logs tell you *who* and
*what*. Anything with client-controlled values (IPs, paths, user agents) is in
the logs only, so a client cannot inflate the metric series.

Both logs are JSON lines on stdout (journald under systemd), emitted when the
request or connection is **over**, so sizes, durations and outcomes are final.
Each target can be routed or silenced on its own, e.g.
`RUST_LOG=info,gfe::conn=off`.

## Where to look

| Question | Metric | Log field |
|---|---|---|
| How many requests, to what? | `gfe_requests_total{listener,host,route,status}` | `method`, `host`, `path`, `route` |
| What do clients get back? | `gfe_requests_total` by `status`; `gfe_grpc_responses_total` by `grpc_status` | `status`, `grpc_status`, `error` |
| How long do requests take? | `gfe_request_duration_seconds` (to the last byte); `gfe_upstream_request_duration_seconds` (backend, to headers) | `duration_ms`, `upstream_ttfb_ms` |
| How big are they? | `gfe_request_body_bytes_total`, `gfe_response_body_bytes_total` | `request_bytes`, `response_bytes` |
| Who are the clients? | — | `client`, `client_port`, `user_agent`, `sni`, `tls_version` |
| Are exchanges broken off? | `gfe_requests_aborted_total{by}`; status `499` | `termination` (`client_abort`, `upstream_abort`) |
| Why do connections end? | `gfe_connections_closed_total{reason}` | connection log `reason`, `error` |
| Is TLS failing, and why? | `gfe_tls_handshake_failures_total{reason}` | connection log `tls_error` |
| What TLS do clients negotiate? | `gfe_tls_connections_total{version,cipher,alpn,resumed}` | `tls_version`, `tls_cipher`, `alpn`, `tls_resumed` |
| How much traffic on the wire? | `gfe_bytes_in_total`, `gfe_bytes_out_total` (TLS included) | connection log `bytes_in`, `bytes_out` |
| Which backend is failing, and how? | `gfe_upstream_errors_total{pool,backend,kind}`, `gfe_backend_health_status` | `pool`, `backend`, `attempts`, `error` |
| How loaded is each backend? | `gfe_upstream_requests_in_flight{pool,backend}` | — |
| Is the node saturated? | `gfe_connections_active / gfe_connections_limit`, `process_open_fds / process_max_fds`, `rate(process_cpu_seconds_total[5m])`, `gfe_runtime_global_queue_depth` | — |
| Is it refusing work? | `gfe_connections_rejected_total{reason="limit"}` | — |
| Did a config or certificate change land? | `gfe_config_last_reload_timestamp`, `gfe_config_reload_errors_total`, `gfe_cert_expiry_timestamp` | node log |

### Reading an outcome

Three fields of the access log together say how a request ended:

- `status` — what the client was sent. `499` is not an HTTP status: it marks a
  request the client abandoned before GFE had any response for it.
- `error` — set when GFE produced the response itself, and why
  (`no_route`, `no_healthy_upstream`, `upstream_connect_refused`,
  `upstream_timeout`, ...). Absent when the backend's response was relayed.
- `termination` — whether the response reached the client in full
  (`complete`), the client left (`client_abort`), or the backend broke off in
  the middle of the body (`upstream_abort`).

For gRPC calls `status` is `200` whatever happened, including when GFE fails
the call itself: read `grpc_status` instead, with `error` saying why.

So a `502` with `error=upstream_connect_refused` is GFE reporting a dead
backend, a `502` without `error` is the backend's own answer, and a `200` with
`termination=client_abort` is a download the client never finished.

### Querying the logs

With the JSON lines in a file or piped from `journalctl -u gfe-node -o cat`:

```bash
# Requests per client IP, busiest first
jq -r 'select(.target=="gfe::access") | .fields.client' | sort | uniq -c | sort -rn | head

# The 20 largest responses: size, client, host and path
jq -r 'select(.target=="gfe::access") | .fields | [.response_bytes, .client, .host, .path] | @tsv' \
  | sort -rn | head -20

# Who is being cut off, by which backend
jq -c 'select(.target=="gfe::access" and .fields.termination!="complete")
       | .fields | {client, host, path, status, termination, backend, duration_ms}'

# Everything about one request, by the id the client or backend reported
jq -c 'select(.fields.request_id=="4f1c...")'

# Why connections from one client end
jq -c 'select(.target=="gfe::conn" and .fields.client=="203.0.113.7")
       | .fields | {reason, error, requests, bytes_in, bytes_out, duration_ms}'
```

In Loki the same questions are `{unit="gfe-node"} | json | target="gfe::access"`
followed by a filter on the extracted fields, e.g.
`| fields_status >= 500 | line_format "{{.fields_client}} {{.fields_path}}"`.

## Below the proxy: packets, drops, interfaces

GFE is a user-space proxy. It sees connections and bytes; it never sees a
packet. Loss, retransmissions, queue overflows and interface faults are kernel
facts, and one of them is invisible to GFE by construction: **a connection the
kernel drops because the listen queue is full never reaches `accept()`**, so
it appears in no GFE metric or log.

Those signals come from [node_exporter](https://github.com/prometheus/node_exporter)
on every GFE node, scraped alongside GFE and joined on `instance`. The
collectors needed are enabled by default:

| Signal | Collector | Metrics |
|---|---|---|
| Packets and bytes per interface | `netdev` | `node_network_{receive,transmit}_{packets,bytes}_total` |
| Interface errors and drops | `netdev` | `node_network_{receive,transmit}_{errs,drop}_total` |
| Link state (including the GRE tunnel from the L4 LB) | `netclass` | `node_network_up`, `node_network_carrier_changes_total` |
| TCP retransmissions and resets | `netstat` | `node_netstat_Tcp_RetransSegs`, `node_netstat_Tcp_OutSegs`, `node_netstat_Tcp_OutRsts` |
| Listen queue overflows (lost connections) | `netstat` | `node_netstat_TcpExt_ListenOverflows`, `node_netstat_TcpExt_ListenDrops` |
| UDP errors (name resolution) | `netstat` | `node_netstat_Udp_InErrors`, `node_netstat_Udp_RcvbufErrors` |
| Sockets in use, orphans, memory | `sockstat` | `node_sockstat_TCP_inuse`, `node_sockstat_TCP_orphan`, `node_sockstat_TCP_mem_bytes` |
| Kernel receive backlog drops | `softnet` | `node_softnet_dropped_total`, `node_softnet_times_squeezed_total` |
| Connection tracking table | `conntrack` | `node_nf_conntrack_entries`, `node_nf_conntrack_entries_limit` |

NIC-level counters (CRC errors, ring buffer overruns) need the `ethtool`
collector, which is off by default: `--collector.ethtool`.

Reading the two layers together:

- **Client aborts rising, with host retransmissions rising** — the network
  path, not the service.
- **Client aborts rising, upstream duration rising, host clean** — a slow
  backend running clients into their timeouts.
- **Connect timeouts reported by clients, nothing in GFE** — look at
  `ListenOverflows`: connections are being lost before GFE can accept them.
- **Handshake failures with `reason="client_closed"`** — clients giving up
  during the handshake: CPU saturation on the node, or loss on the path.

## Alerts and dashboard

- [`deploy/prometheus/gfe-alerts.yml`](../deploy/prometheus/gfe-alerts.yml) —
  alerting rules for availability, latency, saturation, client-side breakage,
  config and certificates, and the host-level network signals above. It
  expects the scrape job to be called `gfe`.
- [`deploy/grafana/gfe-dashboard.json`](../deploy/grafana/gfe-dashboard.json) —
  the same signals as panels, filterable by instance, host and pool.

## What is not recorded, and why

- **Query strings and request headers** (other than `User-Agent`): they carry
  tokens and personal data. The access log has the path only.
- **Request and response bodies.**
- **Per-connection TCP statistics** (round-trip time, retransmissions of one
  client). The kernel exposes them through `TCP_INFO`, for which Rust has no
  safe API; reading it would be the first `unsafe` code in the project. The
  host-level retransmission ratio covers the fleet-wide question.
- **Distributed traces.** `X-Request-Id` is propagated and logged at both
  ends, which correlates a request across GFE and the backend, but GFE does
  not emit spans.
- **Sampling.** Every request and connection is logged. At very high request
  rates, drop or sample a target in the log pipeline rather than in GFE.
