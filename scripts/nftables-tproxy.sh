#!/usr/bin/env bash
set -euo pipefail

# IDIPS TPROXY setup for transparent TCP interception.
#
# Usage:
#   sudo ./scripts/nftables-tproxy.sh
#   sudo ./scripts/nftables-tproxy.sh --cleanup
#
# Adjust POOL and TPROXY_PORT to match the IDIPS settings.
# The pool must be the same Fake-IP pool configured in the admin UI.

POOL="${POOL:-10.100.0.0/16}"
TPROXY_PORT="${TPROXY_PORT:-1082}"
DNS_PORT="${DNS_PORT:-53}"
FWMARK="${FWMARK:-0x1}"
TABLE="${TABLE:-100}"
NFT_TABLE="${NFT_TABLE:-idips}"

if [[ "${1:-}" == "--cleanup" ]]; then
  nft delete table ip "${NFT_TABLE}" 2>/dev/null || true
  ip rule del fwmark "${FWMARK}/${FWMARK}" table "${TABLE}" 2>/dev/null || true
  ip route flush table "${TABLE}" 2>/dev/null || true
  echo "IDIPS TPROXY rules removed."
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Must be run as root." >&2
  exit 1
fi

# Policy routing: marked packets are delivered locally.
ip rule add fwmark "${FWMARK}/${FWMARK}" table "${TABLE}" 2>/dev/null || true
ip route replace local "${POOL}" dev lo table "${TABLE}"

# nftables table/chain.
nft add table ip "${NFT_TABLE}" 2>/dev/null || true
nft add chain ip "${NFT_TABLE}" prerouting \
  '{ type filter hook prerouting priority mangle; policy accept; }' 2>/dev/null || true
nft flush chain ip "${NFT_TABLE}" prerouting 2>/dev/null || true

# Intercept TCP connections to the Fake-IP pool and hand them to IDIPS.
nft add rule ip "${NFT_TABLE}" prerouting \
  ip daddr "${POOL}" meta l4proto tcp \
  meta mark set "${FWMARK}" tproxy to :"${TPROXY_PORT}" accept

# Optional: force client DNS to the local IDIPS resolver. Uncomment if IDIPS
# is the gateway and you want to prevent clients from bypassing the fake-IP DNS.
# nft add rule ip "${NFT_TABLE}" prerouting udp dport 53 redirect to :"${DNS_PORT}"
# nft add rule ip "${NFT_TABLE}" prerouting tcp dport 53 redirect to :"${DNS_PORT}"

echo "IDIPS TPROXY active: pool=${POOL} tproxy=:${TPROXY_PORT} table=${TABLE}"
echo "Enable forwarding if this host is a gateway: sysctl -w net.ipv4.ip_forward=1"
echo "Cleanup: sudo $0 --cleanup"
