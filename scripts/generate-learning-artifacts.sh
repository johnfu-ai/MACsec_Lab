#!/usr/bin/env bash
# Generate reference PCAPs, Markdown field dumps, and optional tshark views.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
export PYTHONPATH="${ROOT}${PYTHONPATH:+:${PYTHONPATH}}"

python3 -m macsec_lab generate --out "${ROOT}/captures"
python3 -m macsec_lab analyze --captures "${ROOT}/captures" --out "${ROOT}/captures/decoded"

DECODE="${ROOT}/captures/decoded"
mkdir -p "${DECODE}"

if command -v tshark >/dev/null 2>&1; then
    echo "=== tshark summary dumps ==="
    tshark -r captures/session-full.pcap -nn \
        > "${DECODE}/07-tshark-session-summary.txt" 2>/dev/null || true
    tshark -r captures/mka-handshake.pcap -Y "mka" -V \
        > "${DECODE}/08-tshark-mka-verbose.txt" 2>/dev/null || true
    tshark -r captures/macsec-lab-encrypted.pcap -Y "macsec" -V \
        > "${DECODE}/09-tshark-macsec-verbose.txt" 2>/dev/null || true
    tshark -r captures/macsec-ieee-gcm-aes-128-encrypt.pcap -Y "macsec" -V \
        > "${DECODE}/10-tshark-ieee-encrypt-verbose.txt" 2>/dev/null || true
    tshark -r captures/mka-after-eap.pcap -Y "eapol or mka" -V \
        > "${DECODE}/12-tshark-mka-after-eap-verbose.txt" 2>/dev/null || true
    tshark -r captures/mka-rekey.pcap -Y "mka or macsec" -V \
        > "${DECODE}/13-tshark-mka-rekey-verbose.txt" 2>/dev/null || true
    tshark -r captures/mka-co30.pcap -Y "mka or macsec" -V \
        > "${DECODE}/14-tshark-mka-co30-verbose.txt" 2>/dev/null || true
    tshark -r captures/mka-xpn.pcap -Y "mka or macsec" -V \
        > "${DECODE}/17-tshark-mka-xpn-verbose.txt" 2>/dev/null || true
    tshark -r captures/mka-multi-peer.pcap -Y "mka or macsec" -V \
        > "${DECODE}/18-tshark-mka-multi-peer-verbose.txt" 2>/dev/null || true
    tshark -r captures/macsec-replay.pcap -Y "macsec" -V \
        > "${DECODE}/19-tshark-macsec-replay-verbose.txt" 2>/dev/null || true
    tshark -r captures/mka-delay-protect.pcap -Y "mka or macsec" -V \
        > "${DECODE}/20-tshark-mka-delay-protect-verbose.txt" 2>/dev/null || true
    tshark -r captures/macsec-ieee-gcm-aes-256-encrypt.pcap -Y "macsec" -V \
        > "${DECODE}/16-tshark-ieee256-encrypt-verbose.txt" 2>/dev/null || true
    tshark -r captures/session-full.pcap -q -z io,phs \
        > "${DECODE}/00-protocol-hierarchy.txt" 2>/dev/null || true
else
    echo "tshark not found; skipped Wireshark dumps (Markdown reports are complete)"
fi

cat > "${DECODE}/README.txt" <<'EOF'
MACsec Lab — decoded learning artifacts
=======================================

01-mka-handshake.md                 每条 MKA 的偏移字段表 + hex + ICV
02-macsec-encrypted.md              加密帧：线上 SecTAG + 解密后 IPv4/ICMP
03-macsec-integrity-only.md         完整性帧：内层明文可见
04-ieee-integrity.md / 05-ieee-encrypt.md  IEEE 官方 GCM 向量
06-session-full.md                  完整会话 13 帧（与 05_wire_format/5.3、5.4 同源）
11-mka-after-eap.md                 EAP-Success 之后的 MKA（Authenticator / Supplicant）
13-mka-rekey.md                     SAK 换钥：AN=0 → AN=1 全过程
14-mka-co30.md                      Confidentiality Offset 30：内层 IP 头明文可见
15/16-ieee-*256.md                  IEEE GCM-AES-256 官方向量（同帧、256-bit key）
17-mka-xpn.md                       XPN：套件 ID 进 Distributed SAK，PN64 越过 2^32 回绕
18-mka-multi-peer.md                多成员 CA：3 节点共享 CAK，一个 KS 一把 SAK，三个 SC
19-macsec-replay.md                 接收端重放窗口：乱序接受、重放/重复帧丢弃（模型 ReplayWindow）
20-mka-delay-protect.md             Delay Protect：SAK Use 宣告 LLPN 下沿，被截留的帧超时即弃
07–10, 12–14, 16–20 tshark          Wireshark 树（若已安装 tshark）

中文总览（含序列图）：05_wire_format/5.3_control_plane_frames.md
EAP vs PSK：05_wire_format/5.5_psk_vs_eap.md


Open the pcaps in Wireshark:
  captures/session-full.pcap
  captures/mka-after-eap.pcap
  Filter:  mka || macsec || eap
EOF

echo ""
echo "=== DONE ==="
ls -lh "${ROOT}/captures"/*.pcap
ls -lh "${DECODE}"
