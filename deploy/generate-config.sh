#!/usr/bin/env bash
# Generate a starter GFE dynamic config (listeners/routes/pools/certs) as JSON.
#
# This is a convenience scaffold; in production the dynamic config is generated
# by your deployment tooling (Puppet/Ansible/git) — see ADR-001.
#
# Usage:
#   ./generate-config.sh --host atlas.example.org \
#       --backend 10.0.0.1:8443 --backend 10.0.0.2:8443 \
#       -o /etc/gfe/gfe-dynamic.json
set -euo pipefail

HOST=""
OUT="/dev/stdout"
BACKENDS=()
VIP="0.0.0.0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2;;
    --backend) BACKENDS+=("$2"); shift 2;;
    --vip) VIP="$2"; shift 2;;
    -o|--out) OUT="$2"; shift 2;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 1;;
  esac
done

if [[ -z "$HOST" || ${#BACKENDS[@]} -eq 0 ]]; then
  echo "error: --host and at least one --backend are required" >&2
  exit 1
fi

ups=""
for b in "${BACKENDS[@]}"; do
  h="${b%:*}"; p="${b##*:}"
  [[ -n "$ups" ]] && ups+=","
  ups+="{\"host\":\"$h\",\"port\":$p,\"weight\":1}"
done

cat > "$OUT" <<JSON
{
  "certificates": [
    { "sni": ["$HOST"], "cert_file": "/etc/gfe/certs/$HOST.fullchain.pem", "key_file": "/etc/gfe/certs/$HOST.key.pem" }
  ],
  "listeners": [
    { "id": "https", "address": "$VIP", "port": 443, "protocol": "https" },
    { "id": "http",  "address": "$VIP", "port": 80,  "protocol": "http"  }
  ],
  "routes": [
    { "id": "$HOST-web", "listener": "https", "host": "$HOST", "path_prefix": "/", "action": { "forward": "$HOST-pool" } },
    { "id": "$HOST-redirect", "listener": "http", "host": "$HOST", "path_prefix": "/", "action": { "redirect": { "scheme": "https", "status": 308 } } }
  ],
  "pools": [
    { "id": "$HOST-pool", "scheme": "https", "lb_policy": "round_robin", "upstreams": [ $ups ],
      "health_check": { "type": "https", "path": "/healthz", "interval": "5s", "timeout": "2s", "healthy_threshold": 2, "unhealthy_threshold": 3 } }
  ]
}
JSON

echo ">> wrote dynamic config to $OUT" >&2
