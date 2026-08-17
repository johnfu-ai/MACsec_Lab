#!/usr/bin/env bash
set -euo pipefail
ip link del br-macsec 2>/dev/null || true
ip netns del macsec-a 2>/dev/null || true
ip netns del macsec-b 2>/dev/null || true
echo "namespaces and bridge removed (captures preserved)"
