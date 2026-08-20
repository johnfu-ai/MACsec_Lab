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

check 1/8 "reference pcaps exist" test -s captures/mka-handshake.pcap -a -s captures/session-full.pcap -a -s captures/mka-after-eap.pcap -a -s captures/mka-rekey.pcap
check 2/8 "keys.json present" test -s captures/keys.json
check 3/8 "decoded MKA report exists" test -s captures/decoded/01-mka-handshake.md -a -s captures/decoded/11-mka-after-eap.md -a -s captures/decoded/13-mka-rekey.md

if command -v tshark >/dev/null; then
    mka=$(tshark -r captures/mka-handshake.pcap -Y mka -T fields -e frame.number 2>/dev/null | wc -l)
    mac=$(tshark -r captures/macsec-lab-encrypted.pcap -Y macsec -T fields -e frame.number 2>/dev/null | wc -l)
    ieee=$(tshark -r captures/macsec-ieee-gcm-aes-128-encrypt.pcap -Y macsec -T fields -e frame.number 2>/dev/null | wc -l)
    check 4/8 "tshark sees >=6 MKA frames (got ${mka})" test "${mka}" -ge 6
    check 5/8 "tshark sees >=6 MACsec frames (got ${mac})" test "${mac}" -ge 6
    check 6/8 "tshark sees IEEE encrypt vector (got ${ieee})" test "${ieee}" -ge 1
    eap=$(tshark -r captures/mka-after-eap.pcap -Y "eap.code == 3" -T fields -e frame.number 2>/dev/null | wc -l)
    eap_mka=$(tshark -r captures/mka-after-eap.pcap -Y mka -T fields -e frame.number 2>/dev/null | wc -l)
    check 7/8 "tshark sees EAP-Success then MKA (eap=${eap} mka=${eap_mka})" test "${eap}" -ge 1 -a "${eap_mka}" -ge 6
    ans=$(tshark -r captures/mka-rekey.pcap -Y macsec -T fields -e macsec.AN 2>/dev/null | sort -u | wc -l)
    check 8/8 "tshark sees rekey story with 2 ANs (got ${ans})" test "${ans}" -ge 2
else
    echo "[SKIP] 4-8 tshark not installed"
fi

if [[ "${fail}" -eq 0 ]]; then
    echo "verify: PASS"
    exit 0
fi
echo "verify: FAIL"
exit 1
