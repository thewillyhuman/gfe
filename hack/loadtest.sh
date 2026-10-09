#!/usr/bin/env bash
# End-to-end load test: mock upstream + the real gfe-node + load client.
#
# Spins everything up on loopback, runs a matrix of scenarios, prints a table,
# tears down. The node runs as it does in production: its access log on and
# written to a file, an ECDSA P-256 certificate on the HTTPS listener. All
# three processes share this host's CPUs, so req/s and latencies are
# conservative/comparative (relative cost per layer), not a tuned NIC
# benchmark; the node's CPU per request, printed with each row, is what
# isolates the node from the two processes it shares the cores with.
#
# Usage: ./hack/loadtest.sh [connections] [duration_secs]
set -euo pipefail

CONNS="${1:-64}"
DUR="${2:-6}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Loopback ports of the run. They stay clear of the ones the demo publishes
# (hack/demo: 18080, 18443, 19000, 19101), so both can run at once.
UPSTREAM_PORT=29000
HTTP_PORT=28080
HTTPS_PORT=28443
UPSTREAM=127.0.0.1:$UPSTREAM_PORT
HTTP=127.0.0.1:$HTTP_PORT
HTTPS=127.0.0.1:$HTTPS_PORT
METRICS=127.0.0.1:29101

echo ">> building release binaries"
cargo build --release -q -p gfe-node -p gfe-loadtest

TMP="$(mktemp -d)"
cleanup() { kill "${UP_PID:-}" "${NODE_PID:-}" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

# A throwaway ECDSA P-256 certificate for the https listener, gone with the
# run: what a node should serve with (an RSA signature costs several times
# as much per full handshake).
openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/key.pem" 2>/dev/null
openssl req -x509 -key "$TMP/key.pem" -out "$TMP/cert.pem" -days 1 -subj "/CN=localhost" 2>/dev/null

cat > "$TMP/dynamic.json" <<JSON
{
  "certificates": [
    { "default": true,
      "cert_file": "$TMP/cert.pem",
      "key_file": "$TMP/key.pem" }
  ],
  "listeners": [
    { "id": "http",  "address": "127.0.0.1", "port": $HTTP_PORT, "protocol": "http"  },
    { "id": "https", "address": "127.0.0.1", "port": $HTTPS_PORT, "protocol": "https" }
  ],
  "routes": [
    { "id": "http-fixed",  "listener": "http",  "host": "*", "path_prefix": "/fixed",  "action": { "fixed": { "status": 200, "body": "ok" } } },
    { "id": "http-proxy",  "listener": "http",  "host": "*", "path_prefix": "/proxy/", "action": { "forward": "demo-pool" } },
    { "id": "https-fixed", "listener": "https", "host": "*", "path_prefix": "/fixed",  "action": { "fixed": { "status": 200, "body": "ok" } } },
    { "id": "https-proxy", "listener": "https", "host": "*", "path_prefix": "/proxy/", "action": { "forward": "demo-pool" } }
  ],
  "pools": [
    { "id": "demo-pool", "scheme": "http", "lb_policy": "round_robin",
      "upstreams": [ { "host": "127.0.0.1", "port": $UPSTREAM_PORT, "weight": 1 } ],
      "health_check": { "type": "tcp", "interval": "2s", "timeout": "1s", "healthy_threshold": 1, "unhealthy_threshold": 3 } }
  ]
}
JSON

# The access log goes to a file, as in production: one line per request
# and per connection is part of what a request costs the node.
cat > "$TMP/node.toml" <<TOML
[node]
id = "gfe-load"
metrics_addr = "$METRICS"
[control_plane]
config_file = "$TMP/dynamic.json"
local_cache = "$TMP/cache.json"
[log]
file = "$TMP/gfe.log"
[health_check_defaults]
TOML

LT=./target/release/gfe-loadtest
NODE=./target/release/gfe-node

echo ">> starting mock upstream ($UPSTREAM)"
"$LT" upstream --listen "$UPSTREAM" --body-bytes 64 >/dev/null 2>&1 &
UP_PID=$!
disown

echo ">> starting gfe-node"
RUST_LOG=info "$NODE" --config "$TMP/node.toml" >"$TMP/node.log" 2>&1 &
NODE_PID=$!
disown

# Wait for readiness: the ops endpoints answer before the listeners are
# bound, with a 503 until they are.
for _ in $(seq 1 50); do
  if curl -sf -o /dev/null "http://$METRICS/readyz"; then break; fi
  sleep 0.1
done

# Run one scenario (its label, then the load client's arguments) and print
# its row, which ends with the node's CPU per request.
scenario() {
  local label="$1"
  shift
  "$LT" run --duration-secs "$DUR" --label "$label" --cpu-of "$NODE_PID" "$@"
}

# Connection churn leaves loopback sockets in TIME_WAIT, which exhausts the
# ephemeral ports: give them a moment to clear before churning again.
settle() {
  local waited=0
  while [ "$waited" -lt 60 ]; do
    local tw
    tw=$( (netstat -an 2>/dev/null || ss -tan 2>/dev/null) | grep -c TIME_WAIT || true)
    [ "$tw" -lt 2000 ] && return
    sleep 1
    waited=$((waited + 1))
  done
}

echo ">> ready; running scenarios (connections=$CONNS, duration=${DUR}s each)"
echo

printf '%-38s %-10s %s\n' "scenario" "mode" "result"
printf '%-38s %-10s %s\n' "--------" "----" "------"

# Reconnect churn exhausts loopback ephemeral ports at high concurrency
# (TIME_WAIT), so the connection-bound rows use low concurrency on purpose.
RECONN_CONNS=8

scenario "http  · fixed (GFE overhead)"      --target "http://$HTTP/fixed"     --connections "$CONNS"        --mode keepalive
scenario "http  · proxy (+upstream)"         --target "http://$HTTP/proxy/x"   --connections "$CONNS"        --mode keepalive
scenario "https · proxy (warm TLS)"          --target "https://$HTTPS/proxy/x" --connections "$CONNS"        --mode keepalive
scenario "https · proxy (resumed TLS/req, c=$RECONN_CONNS)" --target "https://$HTTPS/proxy/x" --connections "$RECONN_CONNS" --mode reconnect
settle
scenario "https · proxy (full TLS/req, c=$RECONN_CONNS)"    --target "https://$HTTPS/proxy/x" --connections "$RECONN_CONNS" --mode reconnect --no-resume

echo
# What the node counted, so that the rows can be read for what they were:
# the TLS connections by version and whether they resumed a session.
echo ">> tls connections, as the node counted them:"
curl -s "http://$METRICS/metrics" | grep '^gfe_tls_connections_total' | sed 's/^/   /'
echo ">> access log: $(wc -l < "$TMP/gfe.log" | tr -d ' ') lines ($(du -h "$TMP/gfe.log" | cut -f1))"
echo ">> done"
