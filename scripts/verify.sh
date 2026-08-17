#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

fail=0
check() {
    local n="$1" msg="$2"
    shift 2
    if "$@"; then
        echo "[PASS] ${n} ${msg}"
    else
        echo "[FAIL] ${n} ${msg}"
        fail=1
    fi
}

check 1/6 "reference pcaps exist" test -s captures/mka-handshake.pcap -a -s captures/session-full.pcap
check 2/6 "keys.json present" test -s captures/keys.json
check 3/6 "decoded MKA report exists" test -s captures/decoded/01-mka-handshake.md

if command -v tshark >/dev/null; then
    mka=$(tshark -r captures/mka-handshake.pcap -Y mka -T fields -e frame.number 2>/dev/null | wc -l)
    mac=$(tshark -r captures/macsec-lab-encrypted.pcap -Y macsec -T fields -e frame.number 2>/dev/null | wc -l)
    ieee=$(tshark -r captures/macsec-ieee-gcm-aes-128-encrypt.pcap -Y macsec -T fields -e frame.number 2>/dev/null | wc -l)
    check 4/6 "tshark sees >=6 MKA frames (got ${mka})" test "${mka}" -ge 6
    check 5/6 "tshark sees >=6 MACsec frames (got ${mac})" test "${mac}" -ge 6
    check 6/6 "tshark sees IEEE encrypt vector (got ${ieee})" test "${ieee}" -ge 1
else
    echo "[SKIP] 4-6 tshark not installed"
fi

if [[ "${fail}" -eq 0 ]]; then
    echo "verify: PASS"
    exit 0
fi
echo "verify: FAIL"
exit 1
