#!/usr/bin/env bash
# Validate a GFE node + dynamic config before deploying it.
#
# Usage:
#   ./validate-config.sh /etc/gfe/gfe.toml
#   GFE_BIN=./target/release/gfe-node ./validate-config.sh config/gfe.example.toml
set -euo pipefail

CONFIG="${1:-/etc/gfe/gfe.toml}"
GFE_BIN="${GFE_BIN:-gfe-node}"

if ! command -v "$GFE_BIN" >/dev/null 2>&1 && [[ ! -x "$GFE_BIN" ]]; then
  echo "error: gfe-node binary not found (set GFE_BIN=path/to/gfe-node)" >&2
  exit 1
fi

echo ">> Validating $CONFIG"
"$GFE_BIN" --config "$CONFIG" --check-config
echo ">> OK"
