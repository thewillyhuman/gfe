# Local demo

One GFE node in front of a handful of backends, clients that behave the way
real clients do, and the monitoring stack around it: Prometheus, Alertmanager,
Loki and Grafana with the dashboards loaded. It exists to explore what GFE
reports, not to measure it.

```bash
cd hack/demo
docker compose up -d --build     # first run builds gfe-node: a few minutes
open http://localhost:13000      # Grafana, no login
docker compose down -v           # remove everything, volumes included
```

Every port is published on `127.0.0.1` only.

| What | Where |
|---|---|
| Grafana (anonymous admin) | http://localhost:13000 |
| Prometheus | http://localhost:19090 |
| Alertmanager | http://localhost:19093 |
| GFE `http` listener | `localhost:18080` |
| GFE `https` listener | `localhost:18443` |
| GFE `grpc` listener (cleartext HTTP/2) | `localhost:19000` |
| GFE `/metrics`, `/healthz`, `/readyz` | http://localhost:19101 |

## What is running

**The node.** `gfe` is built from this repository and configured by
[`gfe/gfe.toml`](../hack/demo/gfe/gfe.toml) and
[`gfe/gfe-dynamic.json`](../hack/demo/gfe/gfe-dynamic.json):
three listeners, eleven routes, seven pools.

| Host | Listener | Goes to |
|---|---|---|
| `shop.demo.local` | https | `web`: three HTTP backends, round robin (`/api/` goes to `api`) |
| `api.demo.local` | https, http | `api`: two backends, least request |
| `media.demo.local` | https | `media`: one steady backend and `flapper`, which is up 90 s and down 30 s, forever |
| `legacy.demo.local` | http | `legacy`: a host with nothing listening |
| `shop.demo.local` | http | a redirect to https |
| any host, `/ping` | http | a fixed response |
| `greeter.demo.local` | grpc | `greeter`: two grpc-java servers, probed with the gRPC health protocol |
| `grpcbin.demo.local` | grpc | `grpcbin`: a grpc-go server with unary, streaming and error methods |
| `grpc-legacy.demo.local` | grpc | a gRPC pool whose backend is gone |

The HTTP backends are [go-httpbin](https://github.com/mccutchen/go-httpbin):
`/status/503`, `/delay/5`, `/bytes/100000`, `/drip` and friends produce any
status, latency or size on demand.

**The clients.** Three containers (three client addresses) run
[`traffic/traffic.sh`](../hack/demo/traffic/traffic.sh): about two thirds healthy requests
over HTTP/1.1, HTTP/2 and gRPC, and one third of what an edge sees every day.
Two of them (`traffic`) sit next to the node. The third (`traffic-far`) is the
same client behind a worse network: 40 ms away and losing 3% of its packets.

| The traffic does | Look for |
|---|---|
| requests a backend answers with 404, 500, 503 | status panels; `Server errors` in the logs dashboard |
| `/delay/5` against a 3 s `upstream_first_byte` | 504, `error=upstream_timeout`, upstream errors `kind="timeout"` |
| requests to the pool whose backend is gone | `no_healthy_upstream`, the `GfeNoHealthyUpstream` alert |
| requests while `flapper` is going down | `connect_refused`, retries, the backend health panel |
| clients that give up before the response | status 499, `Aborted requests`, `termination=client_abort` |
| clients that leave in the middle of a download | status 200 with `termination=client_abort` |
| hosts that have no route | 404 with `error=no_route` |
| plain HTTP sent to the TLS port, an untrusted certificate, TLS 1.1 only | `TLS handshake failures by reason`; the connection log's `tls_error` and `error` |
| gRPC calls that fail on purpose, and one to a dead pool | `gRPC calls by status`; status 14 with `error` set is GFE's own answer |
| a 10-second gRPC server stream | long durations on the `grpcbin` route: streams, not slowness |
| the same requests from the far client | the *Kernel* panels: its round-trip time and retransmissions, which no request metric shows |

**The kernel view.** Like every node, this one attaches a small eBPF program
to its cgroup, which reports, for every TCP connection of the node,
how long it waited to be accepted, its round-trip time, its retransmissions
and how it ended. The panels titled *Kernel: …* on both dashboards are built
on it, and each closed connection is logged as a `gfe::tcp` event. The
container runs as root with `CAP_BPF` and `CAP_NET_ADMIN` for this, because
Docker gives added capabilities to root only; under systemd the unprivileged
service user gets them from the unit,
[`distribution/systemd/gfe-node.service`](../distribution/systemd/gfe-node.service).

**The monitoring.**

- **Prometheus** scrapes the node every 5 s and evaluates
  [`distribution/prometheus/gfe-alerts.yml`](../distribution/prometheus/gfe-alerts.yml).
  Several alerts are meant to fire here; see them under *Alerts* in Prometheus
  or *Alerting* in Grafana.
- **node_exporter** runs inside the node's network namespace, so the packet,
  TCP and interface counters are those of the GFE container.
- **Loki** receives the node's log through **Alloy**. The node writes JSON to
  stdout; the container also `tee`s it to a file that Alloy tails, so nothing
  needs access to the Docker socket.
- **Grafana** has both data sources and two dashboards provisioned:
  - *GFE — General Front End*: the metrics dashboard shipped in
    [`distribution/grafana`](../distribution/grafana).
  - *GFE — Logs*: built from the access, connection and kernel logs, which is
    where the client addresses are. It ranks clients by traffic and by what
    goes wrong for them, and narrows every panel to one client; see
    [Finding a client that has a problem](#finding-a-client-that-has-a-problem).

  *Explore → Loki* is the place for ad-hoc questions, e.g.

  ```logql
  {job="gfe", target="gfe::access"} | json | fields_status >= 500
  {job="gfe", target="gfe::conn"} | json | fields_reason != "closed"
  ```

## Finding a client that has a problem

Client addresses are in the logs only, so that a client cannot inflate the
metric series. This is therefore done on *GFE — Logs*, in two steps.

**Who?** The *Clients* row ranks clients over the selected time range:

| Panel | A client high on it |
|---|---|
| *Requests not completed, by client* | gives up before the answer is complete (`client_abort`), or is cut off by a backend (`upstream_abort`) |
| *Failed TLS handshakes, by client* | cannot negotiate TLS with the node; the name says why |
| *Error responses, by client* | is sent 4xx (its own requests are wrong) or 5xx (the service is) |
| *Connections that did not end cleanly, by client* | has connections that end in anything but an orderly close |
| *Kernel: round-trip time by client* | is far away, or on a slow path |
| *Kernel: retransmitted segments by client* | is on a path that loses packets |

**What exactly?** Type its address into *Client IP* at the top. Every panel
(except *Node events*) and every log panel then shows that client only: its
status codes, the routes and backends it uses, how its connections end, and
each of its requests. The field is a regular expression matched against the
whole address, so `172\.23\..*` selects a network.

Try it with the far client (`docker compose exec traffic-far hostname -i`).
It leads both kernel panels, while errors are the same share of its requests
as of everybody else's: what is wrong with it is its network, not the
service.

## Things to try

Watch the dashboards while doing any of these.

```bash
# Talk to it yourself
curl -H 'Host: api.demo.local' http://localhost:18080/anything/hello
curl -k --resolve shop.demo.local:18443:127.0.0.1 https://shop.demo.local:18443/get
docker compose exec traffic grpcurl -plaintext -authority greeter.demo.local \
    -d '{"name":"me"}' gfe:9000 helloworld.Greeter/SayHello

# Lose a backend, then get it back: health panel, connect errors, retries
docker compose stop web2
docker compose start web2

# Lose a gRPC backend: the gRPC health probe takes it out
docker compose stop greeter1

# Make the far client's network worse, or as good as the others': watch the
# Kernel panels, and note that request latency barely tells them apart
docker compose exec traffic-far tc qdisc replace dev eth0 root netem delay 150ms loss 10%
docker compose exec traffic-far tc qdisc del dev eth0 root

# Rotate the certificate under the running node: picked up within 10 s,
# visible as a step in "Days until cert expiry" and as one reload in the logs
ROTATE=1 docker compose run --rm setup
```

**Hot reload.** Edit [`gfe/gfe-dynamic.json`](../hack/demo/gfe/gfe-dynamic.json) while the
stack runs: change the `/ping` body, add a route, add a listener. The node
reloads within a second (*Node events* in the logs dashboard). Break the file
on purpose (a route to a pool that does not exist) and the node keeps serving
the previous config, counts a reload error and raises
`GfeConfigReloadFailing`.

## Notes

- The two gRPC server images are amd64 only. On Apple Silicon they run
  emulated and need up to a minute to start; until then their calls fail with
  gRPC status 14, which is itself worth a look on the dashboards.
- Always bring the whole project up (`docker compose up -d`), not single
  services: node_exporter lives in the node's network namespace and has to be
  recreated with it.
- The kernel view needs the Docker VM's kernel to allow eBPF, which Docker
  Desktop's does. Where it does not, the node logs why, `gfe_ebpf_attached`
  stays at 0, `GfeKernelViewNotAttached` fires after five minutes and the
  *Kernel* panels stay empty; everything else works.
- The log file grows for as long as the stack runs; `docker compose down -v`
  removes it.
- Grafana runs without a login and with admin rights. That is acceptable for a
  playground bound to localhost and nowhere else.
