# 附录 C：实验室规格

本附录定义本书配套实验室的目的、技术路线与交付边界——当对"这个抓包是怎么来的""为什么不用真实内核栈"有疑问时，答案在这里。

## C.1 目的

在单主机（WSL2）上提供 IEEE 802.1AE MACsec 与 IEEE 802.1X MKA 的学习环境：参考 PCAP、字段级解析器，以及密码学有效的 ICV/SAK 封装——让 Wireshark 的 `mka` / `macsec` 解析器能够直接接受这些帧。

## C.2 为什么不用 `ip macsec` / wpa_supplicant

写作时的 WSL2 内核报告 `# CONFIG_MACSEC is not set`。Docker 容器共享该内核，因此类似 strongSwan 式的"真实协议栈"实验装不了 SecY SA。实验室的替代路线：

1. 用 Python 实现 GCM-AES-128（802.1AE Clause 14）与 MKA 编码（802.1X Clause 9/11）；
2. 提交 ICV 与 IEEE 公开测试向量**逐字节一致**的 PCAP；
3. 可选地用 AF_PACKET 在 veth/网桥上重放这些帧（`sudo make lab`），得到一份真实的线上 tcpdump。

这也解释了[1.4 节](../01_intro/1.4_the_lab.md)的说明：数据面帧是密码学对齐的构造帧，而非内核卸载产物。真实内核部署路径见[第十一章](../11_deployments/11.1_linux.md)。

## C.3 范围

覆盖：

- PSK CAK（静态 CKN/CAK）与 EAP 派生 CAK/CKN（来自 MSK）
- 点对点与多成员 CA（一把 CAK、一把 SAK、每成员各自 SC）
- MKA：Basic、Potential/Live Peer List、Distributed SAK、SAK Use、16 字节 ICV
- MACsec：带与不带显式 SCI 的 SecTAG、机密性与仅完整性、confidentiality offset 30
- 套件：GCM-AES-128（实验室主路径）、GCM-AES-256 IEEE 向量、GCM-AES-XPN-128 故事线（`mka-xpn.pcap`）
- 生命周期：SAK 换钥（AN/KN 轮转）、接收端重放窗口、Delay Protect

范围之外：MKA announcements、VLAN-in-clear、XPN-256 数据面（构造与 XPN-128 相同，仅 SAK 换 32 字节）、802.1AEcg EDE / 多发送 SC。XPN 仅到构造层面——公开草案的 Annex C ICV 留空，没有逐字节向量可对照。

## C.4 交付物

1. `captures/*.pcap` + `keys.json`
2. `macsec_lab` 解析器与 `captures/decoded/*.md`
3. 本书正文（十三章 + 附录）
4. `make test` / `make verify`

## C.5 权限

`make test` / `make generate` 无需 sudo。`make lab` 需要 root（netns、网桥与原始套接字）；`make book` / `make serve` 需要 Node.js 与 npm（Honkit 本地书稿预览）。
