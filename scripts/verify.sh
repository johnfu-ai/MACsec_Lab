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

check 1/12 "reference pcaps exist" test -s captures/mka-handshake.pcap -a -s captures/session-full.pcap -a -s captures/mka-after-eap.pcap -a -s captures/mka-rekey.pcap -a -s captures/mka-co30.pcap -a -s captures/mka-xpn.pcap
check 2/12 "keys.json present" test -s captures/keys.json
check 3/12 "decoded MKA report exists" test -s captures/decoded/01-mka-handshake.md -a -s captures/decoded/11-mka-after-eap.md -a -s captures/decoded/13-mka-rekey.md

if command -v tshark >/dev/null; then
    mka=$(tshark -r captures/mka-handshake.pcap -Y mka -T fields -e frame.number 2>/dev/null | wc -l)
    mac=$(tshark -r captures/macsec-lab-encrypted.pcap -Y macsec -T fields -e frame.number 2>/dev/null | wc -l)
    ieee=$(tshark -r captures/macsec-ieee-gcm-aes-128-encrypt.pcap -Y macsec -T fields -e frame.number 2>/dev/null | wc -l)
    check 4/12 "tshark sees >=6 MKA frames (got ${mka})" test "${mka}" -ge 6
    check 5/12 "tshark sees >=6 MACsec frames (got ${mac})" test "${mac}" -ge 6
    check 6/12 "tshark sees IEEE encrypt vector (got ${ieee})" test "${ieee}" -ge 1
    eap=$(tshark -r captures/mka-after-eap.pcap -Y "eap.code == 3" -T fields -e frame.number 2>/dev/null | wc -l)
    eap_mka=$(tshark -r captures/mka-after-eap.pcap -Y mka -T fields -e frame.number 2>/dev/null | wc -l)
    check 7/12 "tshark sees EAP-Success then MKA (eap=${eap} mka=${eap_mka})" test "${eap}" -ge 1 -a "${eap_mka}" -ge 6
    ans=$(tshark -r captures/mka-rekey.pcap -Y macsec -T fields -e macsec.AN 2>/dev/null | sort -u | wc -l)
    check 8/12 "tshark sees rekey story with 2 ANs (got ${ans})" test "${ans}" -ge 2
    co=$(tshark -r captures/mka-co30.pcap -Y "mka.confidentiality_offset == 1" -T fields -e frame.number 2>/dev/null | wc -l)
    check 9/12 "tshark sees co30 signaled in Distributed SAK (got ${co})" test "${co}" -ge 1
    ieee256=$(tshark -r captures/macsec-ieee-gcm-aes-256-encrypt.pcap -Y macsec -T fields -e frame.number 2>/dev/null | wc -l)
    check 10/12 "tshark sees IEEE 256-bit vector (got ${ieee256})" test "${ieee256}" -ge 1
    ssci=$(tshark -r captures/mka-xpn.pcap -Y "mka.key_server_ssci > 0" -T fields -e frame.number 2>/dev/null | wc -l)
    check 11/12 "tshark sees XPN KS SSCI bytes (got ${ssci})" test "${ssci}" -ge 3
    wrap_hi=$(tshark -r captures/mka-xpn.pcap -Y "macsec.PN == 4294967295" -T fields -e frame.number 2>/dev/null | wc -l)
    wrap_lo=$(tshark -r captures/mka-xpn.pcap -Y "macsec.PN == 1" -T fields -e frame.number 2>/dev/null | wc -l)
    check 12/12 "tshark sees XPN PN wrap FFFFFFFF->1 (hi=${wrap_hi} lo=${wrap_lo})" test "${wrap_hi}" -ge 1 -a "${wrap_lo}" -ge 1
else
    echo "[SKIP] 4-12 tshark not installed"
fi

if [[ "${fail}" -eq 0 ]]; then
    echo "verify: PASS"
    exit 0
fi
echo "verify: FAIL"
exit 1
