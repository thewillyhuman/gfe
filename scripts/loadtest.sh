#!/usr/bin/env bash
# End-to-end load test: mock upstream + the real gfe-node + load client.
#
# Spins everything up on loopback, runs a matrix of scenarios, prints a table,
# tears down. All three processes share this host's CPUs, so numbers are
# conservative/comparative (relative cost per layer), not a tuned NIC benchmark.
#
# Usage: ./scripts/loadtest.sh [connections] [duration_secs]
set -euo pipefail

CONNS="${1:-64}"
DUR="${2:-6}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

UPSTREAM=127.0.0.1:9000
HTTP=127.0.0.1:18080
HTTPS=127.0.0.1:18443
METRICS=127.0.0.1:19191

echo ">> building release binaries"
cargo build --release -q -p gfe-node -p gfe-loadtest

# Ensure dummy certs exist.
if [[ ! -f config/certs/default.cert.pem ]]; then
  mkdir -p config/certs
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out config/certs/default.key.pem 2>/dev/null
  openssl req -x509 -key config/certs/default.key.pem -out config/certs/default.cert.pem -days 3650 -subj "/CN=localhost" 2>/dev/null
fi

TMP="$(mktemp -d)"
cleanup() { kill "${UP_PID:-}" "${NODE_PID:-}" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

cat > "$TMP/dynamic.json" <<JSON
{
  "certificates": [
    { "default": true,
      "cert_file": "$ROOT/config/certs/default.cert.pem",
      "key_file": "$ROOT/config/certs/default.key.pem" }
  ],
  "listeners": [
    { "id": "http",  "address": "127.0.0.1", "port": 18080, "protocol": "http"  },
    { "id": "https", "address": "127.0.0.1", "port": 18443, "protocol": "https" }
  ],
  "routes": [
    { "id": "http-fixed",  "listener": "http",  "host": "*", "path_prefix": "/fixed",  "action": { "fixed": { "status": 200, "body": "ok" } } },
    { "id": "http-proxy",  "listener": "http",  "host": "*", "path_prefix": "/proxy/", "action": { "forward": "demo-pool" } },
    { "id": "https-fixed", "listener": "https", "host": "*", "path_prefix": "/fixed",  "action": { "fixed": { "status": 200, "body": "ok" } } },
    { "id": "https-proxy", "listener": "https", "host": "*", "path_prefix": "/proxy/", "action": { "forward": "demo-pool" } }
  ],
  "pools": [
    { "id": "demo-pool", "scheme": "http", "lb_policy": "round_robin",
      "upstreams": [ { "host": "127.0.0.1", "port": 9000, "weight": 1 } ],
      "health_check": { "type": "tcp", "interval": "2s", "timeout": "1s", "healthy_threshold": 1, "unhealthy_threshold": 3 } }
  ]
}
JSON

cat > "$TMP/node.toml" <<TOML
[node]
id = "gfe-load"
loopback_vip = "127.0.0.1"
metrics_addr = "$METRICS"
[control_plane]
config_file = "$TMP/dynamic.json"
local_cache = "$TMP/cache.json"
[health_check_defaults]
TOML

LT=./target/release/gfe-loadtest
NODE=./target/release/gfe-node

echo ">> starting mock upstream ($UPSTREAM)"
"$LT" upstream --listen "$UPSTREAM" --body-bytes 64 >/dev/null 2>&1 &
UP_PID=$!

echo ">> starting gfe-node"
RUST_LOG=warn "$NODE" --config "$TMP/node.toml" >"$TMP/node.log" 2>&1 &
NODE_PID=$!

# Wait for readiness.
for _ in $(seq 1 50); do
  if curl -s -o /dev/null "http://$METRICS/readyz"; then break; fi
  sleep 0.1
done
echo ">> ready; running scenarios (connections=$CONNS, duration=${DUR}s each)"
echo

printf '%-38s %-10s %s\n' "scenario" "mode" "result"
printf '%-38s %-10s %s\n' "--------" "----" "------"

# Reconnect churn exhausts loopback ephemeral ports at high concurrency
# (TIME_WAIT), so the handshake-bound row uses low concurrency on purpose.
RECONN_CONNS=8

"$LT" run --target "http://$HTTP/fixed"     --connections "$CONNS"        --duration-secs "$DUR" --mode keepalive --label "http  · fixed (GFE overhead)"
"$LT" run --target "http://$HTTP/proxy/x"   --connections "$CONNS"        --duration-secs "$DUR" --mode keepalive --label "http  · proxy (+upstream)"
"$LT" run --target "https://$HTTPS/proxy/x" --connections "$CONNS"        --duration-secs "$DUR" --mode keepalive --label "https · proxy (warm TLS)"
"$LT" run --target "https://$HTTPS/proxy/x" --connections "$RECONN_CONNS" --duration-secs "$DUR" --mode reconnect --label "https · proxy (new TLS/req, c=$RECONN_CONNS)"

echo
echo ">> done"
