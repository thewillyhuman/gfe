# Local demo

One GFE node in front of a handful of backends, clients that behave the way
real clients do, and the monitoring stack around it: Prometheus, Alertmanager,
Loki and Grafana with the dashboards loaded. It exists to explore what GFE
reports, not to measure it.

```bash
cd demo
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
[`gfe/gfe.toml`](gfe/gfe.toml) and [`gfe/gfe-dynamic.json`](gfe/gfe-dynamic.json):
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

**The clients.** Three `traffic` containers (three client addresses) run
[`traffic/traffic.sh`](traffic/traffic.sh): about two thirds healthy requests
over HTTP/1.1, HTTP/2 and gRPC, and one third of what an edge sees every day.

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

**The monitoring.**

- **Prometheus** scrapes the node every 5 s and evaluates
  [`deploy/prometheus/gfe-alerts.yml`](../deploy/prometheus/gfe-alerts.yml).
  Several alerts are meant to fire here; see them under *Alerts* in Prometheus
  or *Alerting* in Grafana.
- **node_exporter** runs inside the node's network namespace, so the packet,
  TCP and interface counters are those of the GFE container.
- **Loki** receives the node's log through **Alloy**. The node writes JSON to
  stdout; the container also `tee`s it to a file that Alloy tails, so nothing
  needs access to the Docker socket.
- **Grafana** has both data sources and two dashboards provisioned:
  - *GFE — General Front End*: the metrics dashboard shipped in
    [`deploy/grafana`](../deploy/grafana).
  - *GFE — Logs*: built from the access and connection logs: top clients by
    requests and bytes, user agents, why GFE answered instead of a backend,
    broken-off exchanges, TLS failures, and the raw logs with a client filter.

  *Explore → Loki* is the place for ad-hoc questions, e.g.

  ```logql
  {job="gfe", target="gfe::access"} | json | fields_status >= 500
  {job="gfe", target="gfe::conn"} | json | fields_reason != "closed"
  ```

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

# Rotate the certificate under the running node: picked up within 10 s,
# visible as a step in "Days until cert expiry" and as one reload in the logs
ROTATE=1 docker compose run --rm setup
```

**Hot reload.** Edit [`gfe/gfe-dynamic.json`](gfe/gfe-dynamic.json) while the
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
- The log file grows for as long as the stack runs; `docker compose down -v`
  removes it.
- Grafana runs without a login and with admin rights. That is acceptable for a
  playground bound to localhost and nowhere else.
