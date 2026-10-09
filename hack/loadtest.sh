#!/usr/bin/env bash
# End-to-end load test: mock upstream + the real gfe-node + load client.
#
# Spins everything up on loopback, runs a matrix of scenarios, prints a table,
# tears down. The node runs as it does in production: its access log on and
# written to a file, an ECDSA P-256 certificate on the HTTPS listener. All
# three processes share this host's CPUs, so req/s and latencies are
# conservative/comparative (relative cost per layer), not a tuned NIC
# benchmark; the node's CPU per request, printed with each row, is what
# isolates the node from the two processes it shares the cores with. A last
# row runs against a node capped at one connection, every other connection
# refused at accept: what refusing a connection costs the node.
#
# Usage: ./hack/loadtest.sh [options] [connections] [duration_secs]
#
#   --out FILE        also append each row to FILE as one JSON line, which
#                     `gfe-loadtest compare` reads
#   --against REF     also build the node of git ref REF, run the matrix
#                     against REF's node and this tree's in turn, ROUNDS
#                     times each, and compare them: the exit status says
#                     whether this tree's node is slower than REF's by more
#                     than TOLERANCE percent on any scenario
#   --rounds N        with --against, rounds per node (default 2)
#   --tolerance PCT   with --against, the tolerance in percent (default 10)
set -euo pipefail

OUT=""
AGAINST=""
ROUNDS=2
TOLERANCE=10
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --against) AGAINST="$2"; shift 2 ;;
    --rounds) ROUNDS="$2"; shift 2 ;;
    --tolerance) TOLERANCE="$2"; shift 2 ;;
    --*) echo "unknown option: $1" >&2; exit 2 ;;
    *) break ;;
  esac
done
CONNS="${1:-64}"
DUR="${2:-6}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# The idle-connections row holds thousands of sockets open on both sides,
# and the node inherits this shell's limit on open files: raise it where
# the hard limit allows, and size the row to what is allowed.
ulimit -n 16384 2>/dev/null || true
IDLE_CONNS=$(( $(ulimit -n) / 4 ))
[ "$IDLE_CONNS" -gt 2000 ] && IDLE_CONNS=2000

# Loopback ports of the run. They stay clear of the ones the demo publishes
# (hack/demo: 18080, 18443, 19000, 19101), so both can run at once.
UPSTREAM_PORT=29000
HTTP_PORT=28080
HTTPS_PORT=28443
UPSTREAM=127.0.0.1:$UPSTREAM_PORT
HTTP=127.0.0.1:$HTTP_PORT
HTTPS=127.0.0.1:$HTTPS_PORT
METRICS=127.0.0.1:29101

TMP="$(mktemp -d)"
NODE_PID=""
cleanup() {
  kill "${UP_PID:-}" "${NODE_PID:-}" 2>/dev/null || true
  [ -d "$TMP/base" ] && git worktree remove --force "$TMP/base" 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT

echo ">> building release binaries"
cargo build --release -q -p gfe-node -p gfe-loadtest
LT=./target/release/gfe-loadtest
HEAD_NODE="$TMP/gfe-node.head"
cp target/release/gfe-node "$HEAD_NODE"

if [ -n "$AGAINST" ]; then
  echo ">> building the node of $AGAINST"
  git worktree add --quiet --detach "$TMP/base" "$AGAINST"
  # Into this tree's target directory, so that the dependencies are not
  # compiled a second time; the binary is copied out, since this tree's
  # next build replaces it.
  cargo build --release -q --manifest-path "$TMP/base/Cargo.toml" --target-dir target -p gfe-node
  BASE_NODE="$TMP/gfe-node.base"
  cp target/release/gfe-node "$BASE_NODE"
fi

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

# The same node capped at one connection: with one held open, every other
# connection is accepted and closed at once, as over any connection limit.
sed 's/^id = "gfe-load"$/id = "gfe-load-capped"/; /^\[log\]$/i\
[limits]\
max_connections = 1
' "$TMP/node.toml" > "$TMP/node-capped.toml"

echo ">> starting mock upstream ($UPSTREAM)"
"$LT" upstream --listen "$UPSTREAM" --body-bytes 64 >/dev/null 2>&1 &
UP_PID=$!
disown

# Start the node binary $1 on the bootstrap config $2 and wait until it is
# ready: the ops endpoints answer before the listeners are bound, with a
# 503 until they are.
start_node() {
  RUST_LOG=info "$1" --config "$2" >>"$TMP/node.log" 2>&1 &
  NODE_PID=$!
  disown
  for _ in $(seq 1 100); do
    if curl -sf -o /dev/null "http://$METRICS/readyz"; then return; fi
    sleep 0.1
  done
  echo "the node did not become ready; its log:" >&2
  cat "$TMP/node.log" >&2
  exit 1
}

# Stop the running node and wait until it has left.
stop_node() {
  kill "$NODE_PID" 2>/dev/null || true
  for _ in $(seq 1 100); do
    if ! kill -0 "$NODE_PID" 2>/dev/null; then
      NODE_PID=""
      return
    fi
    sleep 0.1
  done
  kill -9 "$NODE_PID" 2>/dev/null || true
  NODE_PID=""
}

# Run one scenario (its label, then the load client's arguments) against
# the running node and print its row, which ends with the node's CPU per
# request; the row is also appended to $JSON_OUT when that is set.
scenario() {
  local label="$1"
  shift
  "$LT" run --duration-secs "$DUR" --label "$label" --cpu-of "$NODE_PID" \
    ${JSON_OUT:+--json-out "$JSON_OUT"} "$@"
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

# Reconnect churn exhausts loopback ephemeral ports at high concurrency
# (TIME_WAIT), so the connection-bound rows use low concurrency on purpose.
RECONN_CONNS=8

# The matrix of scenarios, against the running node. Two rows are the
# workload of a telemetry collector behind the node: requests of a few
# hundred KiB, where a node is bound by bytes, not by requests; and
# thousands of kept connections that seldom send, which the requests of
# the others should not pay for.
matrix() {
  printf '%-38s %-10s %s\n' "scenario" "mode" "result"
  printf '%-38s %-10s %s\n' "--------" "----" "------"
  scenario "http  · fixed (GFE overhead)"      --target "http://$HTTP/fixed"     --connections "$CONNS"        --mode keepalive
  scenario "http  · proxy (+upstream)"         --target "http://$HTTP/proxy/x"   --connections "$CONNS"        --mode keepalive
  scenario "http  · upload 400KiB (+upstream)" --target "http://$HTTP/proxy/up"  --connections "$CONNS"        --mode keepalive --upload-bytes 409600
  scenario "https · proxy (warm TLS)"          --target "https://$HTTPS/proxy/x" --connections "$CONNS"        --mode keepalive
  scenario "https · proxy + $IDLE_CONNS idle conns"   --target "https://$HTTPS/proxy/x" --connections "$CONNS"        --mode keepalive --idle-connections "$IDLE_CONNS"
  scenario "https · proxy (resumed TLS/req, c=$RECONN_CONNS)" --target "https://$HTTPS/proxy/x" --connections "$RECONN_CONNS" --mode reconnect
  settle
  scenario "https · proxy (full TLS/req, c=$RECONN_CONNS)"    --target "https://$HTTPS/proxy/x" --connections "$RECONN_CONNS" --mode reconnect --no-resume
  echo
  # What the node counted, so that the rows can be read for what they were:
  # the TLS connections by version and whether they resumed a session.
  echo ">> tls connections, as the node counted them:"
  curl -s "http://$METRICS/metrics" | grep '^gfe_tls_connections_total' | sed 's/^/   /'
  echo ">> access log: $(wc -l < "$TMP/gfe.log" | tr -d ' ') lines ($(du -h "$TMP/gfe.log" | cut -f1))"
  : > "$TMP/gfe.log"
}

# Against the capped node: one connection held open, and every other one
# closed at accept. The row's "requests" are refused connections, and its
# CPU per request is what refusing a connection costs the node, which a
# flood of connections pays for each of them.
refused_row() {
  scenario "http  · refused at max_connections (c=$RECONN_CONNS)" --target "http://$HTTP/fixed" --connections "$RECONN_CONNS" --mode refused --idle-connections 1
  echo ">> connections refused, as the node counted them:"
  curl -s "http://$METRICS/metrics" | grep '^gfe_connections_rejected_total' | sed 's/^/   /'
  echo
}

# The whole run against the node binary $1: the matrix on the node as
# configured, then the refused row on the node capped at one connection.
run_against() {
  settle
  start_node "$1" "$TMP/node.toml"
  matrix
  stop_node
  settle
  start_node "$1" "$TMP/node-capped.toml"
  refused_row
  stop_node
}

echo ">> ready; running scenarios (connections=$CONNS, duration=${DUR}s each)"
echo

if [ -z "$AGAINST" ]; then
  JSON_OUT="$OUT"
  run_against "$HEAD_NODE"
  echo ">> done"
  exit 0
fi

# The two nodes in turn, so that whatever else the host does during the
# run weighs on both; the comparison takes the best round of each.
HEAD_OUT="${OUT:-$TMP/head.jsonl}"
BASE_OUT="$TMP/base.jsonl"
for round in $(seq 1 "$ROUNDS"); do
  for side in base head; do
    if [ "$side" = base ]; then
      echo ">> round $round of $ROUNDS: the node of $AGAINST"
      bin="$BASE_NODE"
      JSON_OUT="$BASE_OUT"
    else
      echo ">> round $round of $ROUNDS: this tree's node"
      bin="$HEAD_NODE"
      JSON_OUT="$HEAD_OUT"
    fi
    run_against "$bin"
  done
done

echo ">> this tree's node against the node of $AGAINST, on the best round of each:"
"$LT" compare --base "$BASE_OUT" --head "$HEAD_OUT" --tolerance "$TOLERANCE"
