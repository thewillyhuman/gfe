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

Both logs are JSON lines, emitted when the request or connection is **over**,
so sizes, durations and outcomes are final. Each target can be silenced on
its own, e.g. `RUST_LOG=info,gfe::conn=off`.

Where they go is set by `[log] file` in the bootstrap config:

- **With a file** (`/var/log/gfe/gfe.log` in the example config) every line is
  appended to it, and standard output keeps the node's own log only. This is
  the setting for a node that carries traffic: point a log collector at the
  file and let it, or logrotate, rotate it.
- **Without one** everything goes to standard output, which under systemd is
  the journal. journald discards what exceeds its rate limit (10,000 lines
  per 30 seconds per service by default) and says so only in its own log, so
  above a few hundred requests a second the access log has holes that nothing
  in GFE can see.

## Where to look

| Question | Metric | Log field |
|---|---|---|
| How many requests, to what? | `gfe_requests_total{listener,vhost,route,status}` | `method`, `host`, `path`, `route` |
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
| Is a pool at its `max_in_flight` quota? | `gfe_upstream_pool_full_total{pool}`; `sum by (pool) (gfe_upstream_requests_in_flight)` against the quota | `error=upstream_pool_full`, `pool` |
| Is a slow exchange the network's fault? (kernel view) | `gfe_client_tcp_rtt_seconds`, `gfe_client_tcp_retransmits_total / gfe_client_tcp_segments_sent_total` | `gfe::tcp`: `rtt_ms`, `retransmits`, joined on `client` + `client_port` |
| Is a backend far, or slow? (kernel view) | `gfe_upstream_tcp_rtt_seconds{backend}` against `gfe_upstream_request_duration_seconds` | `gfe::tcp` with `side=upstream` |
| Is the node keeping up with new connections? (kernel view) | `gfe_accept_queue_wait_seconds{listener}` | connection log `accept_wait_ms` |
| Is the node saturated? | `gfe_connections_active / gfe_connections_limit`, `process_open_fds / process_max_fds`, `rate(process_cpu_seconds_total[5m])`, `gfe_runtime_global_queue_depth` | — |
| Is it refusing work? | `gfe_connections_rejected_total{reason="limit"}` | — |
| Is the log complete? | `gfe_log_lost_lines{destination}` | — |
| Did a config or certificate change land? | `gfe_config_reload_failed` (1 until a reload succeeds), `gfe_config_last_reload_timestamp`, `gfe_config_reload_errors_total`, `gfe_cert_expiry_timestamp` | node log |
| Did an upgrade in place land? | `gfe_upgrade_failures_total` (above 0 until the process is replaced); `process_start_time_seconds` moves when it did | node log, from both processes; `systemctl status` |

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

With the JSON lines in the log file, or piped from
`journalctl -u gfe-node -o cat` on a node without one:

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

## The kernel's view of the node's connections

Optional (`[ebpf] enabled = true`). A small eBPF program attached to the
node's cgroup reports what only the kernel knows about each of the node's TCP
connections: how long it waited to be accepted, its round-trip time, how many
segments had to be retransmitted, and whether it ended with an orderly close.

It watches the node's **sockets**, not packets on an interface, so it works
the same way whether clients reach the node through `lb` and its tunnel or
directly, for instance behind a DNS load balancer.

Each closed connection is counted in the `gfe_client_tcp_*` or
`gfe_upstream_tcp_*` metrics and logged as a `gfe::tcp` event. For a client
connection that event carries the same `client` and `client_port` as the
`gfe::conn` event, which is how the two are joined:

```bash
# Clients whose connections needed retransmissions, worst first
jq -r 'select(.target=="gfe::tcp" and .fields.side=="client" and .fields.retransmits > 0)
       | .fields | [.retransmits, .rtt_ms, .client] | @tsv' | sort -rn | head
```

While a node is upgraded in place, the outgoing process and its successor are
in the same cgroup and each has its own program attached. The outgoing one
stops reporting the moment its successor takes over, so nothing is reported
twice. The connections it is still draining then have a `gfe::conn` event but
no `gfe::tcp` event.

It needs Linux, `CAP_BPF` and `CAP_NET_ADMIN` (the drop-in
`src/systemd/gfe-node-ebpf.conf` grants them under systemd). If it cannot be
attached, the node logs why, sets `gfe_ebpf_attached` to 0 and runs without it.
`gfe_ebpf_enabled` is 1 whenever the config asks for it, attached or not, so
`gfe_ebpf_enabled == 1 and gfe_ebpf_attached == 0` is a node that should have
the kernel view and does not; the shipped rules alert on it
(`GfeKernelViewNotAttached`).

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
| Link state (including the GRE tunnel from the L4 LB) | `netclass` | `node_network_info{adminstate,operstate}`, `node_network_carrier_changes_total` |
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

- [`src/prometheus/gfe-alerts.yml`](../src/prometheus/gfe-alerts.yml) —
  alerting rules for availability, latency, saturation, client-side breakage,
  config and certificates, and the host-level network signals above. It
  expects the scrape job to be called `gfe`.
- [`src/grafana/gfe-dashboard.json`](../src/grafana/gfe-dashboard.json) —
  the same signals as panels, filterable by instance, virtual host and pool.

## What is not recorded, and why

- **Query strings and request headers** (other than `User-Agent`): they carry
  tokens and personal data. The access log has the path only.
- **Request and response bodies.**
- **Per-connection TCP statistics without the kernel view.** Round-trip
  time, retransmissions and the accept-queue wait come from the optional eBPF
  program (`[ebpf] enabled = true`). Without it, only the host-level
  retransmission ratio from node_exporter is available.
- **Distributed traces.** `X-Request-Id` is propagated and logged at both
  ends, which correlates a request across GFE and the backend, but GFE does
  not emit spans.
- **Sampling.** Every request and connection is logged. At very high request
  rates, drop or sample a target in the log pipeline rather than in GFE.

## When the log cannot keep up

Writing the log never makes a request wait. Lines are queued and written by a
thread of their own; if the destination is slower than the node logs, the
queue fills and further lines are dropped. That is deliberate: a front end
that stalls because its log is slow fails everybody, while a log with a hole
in it fails nobody, provided the hole is known. `gfe_log_lost_lines` counts
the lines that were never written, per destination (`file`, `stdout`), and
`GfeLogLinesLost` alerts on it. It also counts lines the destination refused:
a full disk, or a log file that was rotated away and cannot be created again.
