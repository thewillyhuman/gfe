#!/usr/bin/env bash
# Onboard a GFE node as a backend of the L4 `lb` load balancer.
#
# GFE sits behind the L4 LB, which GRE-encapsulates client packets to it. For
# the decapsulated packets (addressed to the service VIP) to reach GFE's
# listening socket, the node needs:
#   1. a GRE tunnel interface that decapsulates packets from the LB nodes, and
#   2. the service VIP on its loopback with ARP suppressed (Direct Server Return).
#
# Run as root on each GFE node. Idempotent-ish: re-running re-applies settings.
#
# Usage:
#   sudo ./backend-onboard.sh --vip 188.184.100.10 --node-ip 188.185.20.7
set -euo pipefail

VIP=""
NODE_IP=""
GRE_DEV="gre-lb"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vip) VIP="$2"; shift 2;;
    --node-ip) NODE_IP="$2"; shift 2;;
    --gre-dev) GRE_DEV="$2"; shift 2;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 1;;
  esac
done

if [[ -z "$VIP" || -z "$NODE_IP" ]]; then
  echo "error: --vip and --node-ip are required" >&2
  exit 1
fi

echo ">> Creating GRE tunnel $GRE_DEV (local $NODE_IP)"
if ! ip link show "$GRE_DEV" >/dev/null 2>&1; then
  ip tunnel add "$GRE_DEV" mode gre local "$NODE_IP" ttl 64
fi
ip link set "$GRE_DEV" up

echo ">> Adding VIP $VIP/32 to loopback (DSR)"
ip addr add "$VIP/32" dev lo 2>/dev/null || echo "   (already present)"

echo ">> Suppressing ARP for the VIP on non-loopback interfaces"
sysctl -w net.ipv4.conf.all.arp_ignore=1
sysctl -w net.ipv4.conf.all.arp_announce=2

echo ">> Done. GFE on this node can now receive GRE-decapsulated traffic for $VIP"
echo "   Verify: ip addr show dev lo | grep $VIP ; ip link show $GRE_DEV"
