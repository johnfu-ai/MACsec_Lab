MACsec Lab — decoded learning artifacts
=======================================

01-mka-handshake.md                 每条 MKA 的偏移字段表 + hex + ICV
02-macsec-encrypted.md              加密帧：线上 SecTAG + 解密后 IPv4/ICMP
03-macsec-integrity-only.md         完整性帧：内层明文可见
04-ieee-integrity.md / 05-ieee-encrypt.md  IEEE 官方 GCM 向量
06-session-full.md                  完整会话 13 帧（与 docs/protocol-analysis.md 同源）
11-mka-after-eap.md                 EAP-Success 之后的 MKA（Authenticator / Supplicant）
13-mka-rekey.md                     SAK 重加密：AN=0 → AN=1 换钥全过程
07–10, 12–13 tshark                 Wireshark 树（若已安装 tshark）

中文总览（含序列图）：docs/protocol-analysis.md
EAP vs PSK：docs/mka-protocol-analysis.md


Open the pcaps in Wireshark:
  captures/session-full.pcap
  captures/mka-after-eap.pcap
  Filter:  mka || macsec || eap
