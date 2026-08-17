#!/usr/bin/env bash
# Live lab: two netns + veth, replay session-full.pcap, capture on the wire.
# Does NOT need CONFIG_MACSEC — frames are injected with AF_PACKET.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS_A=macsec-a
NS_B=macsec-b
BR=br-macsec
RUN="${ROOT}/run"
CAP="${ROOT}/captures/live-session.pcap"

if [[ ${EUID} -ne 0 ]]; then
    echo "run as root: sudo $0"
    exit 1
fi

mkdir -p "${RUN}" "${ROOT}/captures"
export PYTHONPATH="${ROOT}"

cleanup() {
    ip link del "${BR}" 2>/dev/null || true
    ip netns del "${NS_A}" 2>/dev/null || true
    ip netns del "${NS_B}" 2>/dev/null || true
}
trap cleanup EXIT

cleanup || true
sleep 0.2

ip netns add "${NS_A}"
ip netns add "${NS_B}"
ip link add "${BR}" type bridge
ip link set "${BR}" up

ip link add veth-a type veth peer name veth-a-br
ip link add veth-b type veth peer name veth-b-br
ip link set veth-a netns "${NS_A}"
ip link set veth-b netns "${NS_B}"
ip link set veth-a-br master "${BR}"
ip link set veth-b-br master "${BR}"
ip link set veth-a-br up
ip link set veth-b-br up

ip netns exec "${NS_A}" ip link set lo up
ip netns exec "${NS_B}" ip link set lo up
ip netns exec "${NS_A}" ip link set veth-a address 02:00:00:00:00:0a
ip netns exec "${NS_B}" ip link set veth-b address 02:00:00:00:00:0b
ip netns exec "${NS_A}" ip addr add 10.10.0.10/24 dev veth-a
ip netns exec "${NS_B}" ip addr add 10.10.0.20/24 dev veth-b
ip netns exec "${NS_A}" ip link set veth-a up
ip netns exec "${NS_B}" ip link set veth-b up
# Forward PAE group address (01:80:c2:00:00:03) across the bridge.
if [[ -w /sys/class/net/${BR}/bridge/group_fwd_mask ]]; then
    echo 8 > "/sys/class/net/${BR}/bridge/group_fwd_mask"
fi

python3 -m macsec_lab generate --out "${ROOT}/captures"

echo "capturing on ${BR} -> ${CAP}"
tcpdump -i "${BR}" -U -w "${CAP}" ether proto 0x888e or ether proto 0x88e5 >/dev/null 2>&1 &
echo $! > "${RUN}/tcpdump.pid"
sleep 0.4

# Inject from both namespaces so SA MAC matches the veth.
ip netns exec "${NS_A}" python3 -m macsec_lab inject --iface veth-a --pcap session-full.pcap --delay 0.02
sleep 0.3

kill -INT "$(cat "${RUN}/tcpdump.pid")" 2>/dev/null || true
wait "$(cat "${RUN}/tcpdump.pid")" 2>/dev/null || true
rm -f "${RUN}/tcpdump.pid"

echo "live capture: ${CAP} ($(stat -c%s "${CAP}") bytes)"
if command -v tshark >/dev/null; then
    tshark -r "${CAP}" -nn | head -40
fi
