# MACsec vs IPsec / TLS / WireGuard：四层加密协议对比

同一个问题（"把流量保护起来"）在不同层有不同答案。本文把四个主流协议摆在一起对照——先横向总表，再逐对细看，最后给选型与叠加。IPsec 部分对照 [IPsec_Lab](https://github.com/johnfu-ai/IPsec_Lab)。

## 1. 横向总表

| | **MACsec**（本仓库） | **IPsec**（IPsec_Lab） | **TLS 1.3** | **WireGuard** |
|---|---|---|---|---|
| 层 | 以太网（L2） | IP（L3） | 传输层之上（L4+） | UDP 之上的 L3 隧道 |
| 标准 | IEEE 802.1AE/-X | IETF RFC 4301 系 | IETF RFC 8446 | Jason Donenfeld 原创；IETF 无 RFC |
| 控制面/握手 | MKA（EAPOL type 5，组播） | IKEv2（UDP 500/4500） | TLS 握手（1-RTT） | Noise IK（1-RTT，UDP 51820） |
| 数据面 | EtherType `0x88E5` + SecTAG | ESP（IP proto 50） | record 层 AEAD | UDP 载荷 ChaCha20-Poly1305 |
| 数据面算法 | GCM-AES-128/256/XPN | AES-GCM / ChaCha20-Poly1305 等 | AES-GCM / ChaCha20-Poly1305 | ChaCha20-Poly1305 固定 |
| 序号/nonce | PN（32/64 位）+ SCI‖PN | ESP SN + SPI | record seq ⊕ 静态 IV | 64 位 counter（低位进 nonce，兼作重放拒绝） |
| 完整性保护范围 | DA/SA/SecTAG/（co 内）明文头 | 整个 IP 包（隧道模式） | 记录头之外全部 | 整个内层包 |
| 加密粒度 | 每跳每链路 | 端到端（跨路由器） | 每连接每应用 | 点对点隧道 |
| 身份/密钥来源 | CAK（PSK 或 EAP/证书→MSK） | 证书/PSK（IKE AUTH） | X.509 证书/PSK | 静态公钥（Curve25519） |
| **PFS** | **无**（CAK 长期秘密；泄露可解历史 SAK） | 有（DH 每会话） | 有（ECDHE 强制） | 有（每次握手） |
| 组播/多成员 | 原生（组密钥 CA，`mka-multi-peer.pcap`） | 有限（GDOI/组播 ESP 少用） | 不适用 | 不适用（点对点） |
| 抗重放 | PN 窗口 + delay protect（LPN） | ESP 序号窗口 | record 序号 | counter 拒绝 |
| NAT 穿越 | 不涉及（L2 点对点链路） | 需 UDP 封装（4500） | 天然（TCP） | 天然（UDP，还支持端点漫游） |
| MTU 开销 | +24 B（无 SCI）/ +32 B（带 SCI） | 隧道模式 +50~70 B | 每记录 +~20 B + TCP/IP 头 | +32 B + UDP/IP 28 B |
| 硬件卸载 | 网卡普遍线速（[deployments.md](deployments.md)） | 部分网卡/专用设备 | CPU（kTLS 除外） | CPU |
| 典型场景 | 交换机间/主机-交换机链路、DCI、5G 回传 | 站点到站点 VPN、远程接入 | 应用/服务间（HTTPS） | 点对点组网、个人 VPN |

## 2. MACsec vs IPsec（细节）

| | MACsec | IPsec |
|---|---|---|
| 通道标识 | SCI | SPI |
| 控制面认证 | AES-CMAC(ICK) | IKE AUTH（签名/PSK） |
| "PSK" 的含义 | 预共享 **CAK+CKN**；SAK 仍由 KS 生成分发 | 预共享 IKE 认证凭据；ESP 密钥仍由 IKE 派生 |
| 数据面密钥 | SAK（KS 随机生成，**不是** KDF(CAK)） | ESP 密钥从 IKE keymat 派生 |
| 换钥触发 | PN 耗尽（32 位很快）或策略 | 生命周期/流量计数策略 |
| 范围 | 单跳（下一台 SecY 解开） | 端到端或跨 WAN 隧道 |

关键差异一句话：**MACsec 保护"链路"，IPsec 保护"路径"**。MACsec 帧过路由器就解开了；IPsec 包穿过多少路由器都密着。

## 3. MACsec vs TLS

- **位置**：TLS 在传输层之上——端口/连接粒度；MACsec 对全部以太网流量（含 ARP/ICMP/其他 EtherType）无差别保护。
- **身份**：TLS 端点用证书互相认证（服务器必、客户端可选）；MACsec 身份 = CA 成员资格（组密钥，成员间不可区分，[attacks.md](attacks.md) §8）。
- **连接性**：TLS 每连接一次握手（0/1-RTT）；MACsec 一次 MKA 会话管整条链路，无逐流状态。
- **语义**：TLS 保护"这个 socket"；MACsec 保护"这条线"。数据库/服务间常见组合：TLS 管应用身份与端到端，MACsec 管物理链路窃听。

## 4. MACsec vs WireGuard

- WireGuard 是**点对点隧道**：静态公钥配对、无 PKI、无组密钥；MACsec 是**链路协议**：组密钥 CA、可含 N 成员。
- WireGuard 依赖 IP/UDP（要 IP 可达、吃 MTU、过 NAT）；MACsec 在以太网里跑（无 IP 依赖，交换机口对交换机口即可）。
- WireGuard 密码学固定且极简（~4k 行内核代码，易审计）；MACsec 套件族由标准演进（128→256→XPN，[cipher-suites.md](cipher-suites.md)）。
- 二者都常见于"底层链路+上层隧道"的组合——例如云上 DCI 用 MACsec，跨云用 WireGuard。

## 5. 怎么选

| 需求 | 首选 |
|---|---|
| 交换机-交换机/主机-交换机链路加密，线速，不改动 IP | **MACsec** |
| 站点到站点跨 WAN，路由可达即可 | IPsec（IKEv2） |
| 应用/微服务间认证+加密，身份到服务 | TLS |
| 点对点小组网、简单运维、漫游端点 | WireGuard |
| 合规要求"介质上全部密文"（DCI/运营商回传） | MACsec（常叠加上层） |

## 6. 叠加：不是二选一

四者可以同时存在于一条流量路径，每层剥掉一层：

```
[App data]
  ← TLS record            (应用端到端)
  ← TCP/IP
  ← WireGuard UDP 隧道    (跨站点点对点, 可选)
  ← IP/路由
  ← MACsec SecTAG+GCM     (每条以太网链路, 本仓库)
  ← 以太网帧上线
```

代价逐层累计：**MTU 每层缩一次**（MACsec 24/32 B + WG 60 B + TLS 记录头），而且密码学开销叠加。实践原则：**同一跳不要套两层同功能保护**；按信任边界分层——物理链路 MACsec、跨不可信域 IPsec/WG、应用身份 TLS。

> 三件套各自抓包对照：MACsec → 本仓库全部 pcap；IPsec → IPsec_Lab；TLS/WireGuard → 抓 `tcp.port==443` / `udp.port==51820` 即可，重点看握手里的密钥交换与 record/数据面的 nonce 构造——与本文第 1 表逐行对上。
