#!/usr/bin/env bash
# Validate a GFE node + dynamic config before deploying it.
#
# With a second argument, that candidate dynamic config is validated instead of
# the deployed one named in the bootstrap config. This is the form to use as a
# pre-flight gate in config management, e.g. Puppet:
#
#   validate_cmd => '/usr/bin/gfe-node --config /etc/gfe/gfe.toml --check-config --dynamic-config %'
#
# Usage:
#   ./validate-config.sh /etc/gfe/gfe.toml
#   ./validate-config.sh /etc/gfe/gfe.toml /tmp/gfe-dynamic.candidate.json
#   GFE_BIN=./target/release/gfe-node ./validate-config.sh config/gfe.example.toml
set -euo pipefail

CONFIG="${1:-/etc/gfe/gfe.toml}"
CANDIDATE="${2:-}"
GFE_BIN="${GFE_BIN:-gfe-node}"

if ! command -v "$GFE_BIN" >/dev/null 2>&1 && [[ ! -x "$GFE_BIN" ]]; then
  echo "error: gfe-node binary not found (set GFE_BIN=path/to/gfe-node)" >&2
  exit 1
fi

if [[ -n "$CANDIDATE" ]]; then
  echo ">> Validating $CONFIG with candidate dynamic config $CANDIDATE"
  "$GFE_BIN" --config "$CONFIG" --check-config --dynamic-config "$CANDIDATE"
else
  echo ">> Validating $CONFIG"
  "$GFE_BIN" --config "$CONFIG" --check-config
fi
echo ">> OK"
