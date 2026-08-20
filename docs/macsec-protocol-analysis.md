# MACsec (IEEE 802.1AE) 报文解析

数据面：SecY 用 **SAK** 保护用户帧。CAK / CKN / KEK / ICK 都不进入 GCM。SAK 从哪来见 [key-hierarchy.md](key-hierarchy.md)；控制面（谁生成 SAK、怎么发给对端）见 [mka-protocol-analysis.md](mka-protocol-analysis.md)。

- [docs/mka-protocol-analysis.md](mka-protocol-analysis.md)、[docs/macsec-protocol-analysis.md](macsec-protocol-analysis.md) 讲格式
- **每一条线上消息的字段拆解**见 [docs/protocol-analysis.md](protocol-analysis.md)（由 `make generate` 根据 pcap 生成）

## 1. 以太网位置

```
[ DA 6 ][ SA 6 ][ 0x88E5 ][ TCI/AN 1 | SL 1 | PN 4 | SCI 0或8 ][ Secure Data ][ ICV 16 ]
```

`0x88E5` **算在 SecTAG 里**（802.1AE Clause 9）。GCM 的 AAD 从 DA 开始，包含这两个字节。

## 2. TCI / AN（第 1 字节）

bit 8 是 MSB：

| 位 | 掩码 | 含义 |
|---|---|---|
| V | `0x80` | 版本，**当前必须为 0** |
| ES | `0x40` | End Station。源 MAC 即 SCI 的 MAC 时置 1；ES=1 时不要再置 SC |
| SC | `0x20` | SecTAG **显式携带 8 字节 SCI** |
| SCB | `0x10` | EPON Single Copy Broadcast |
| E | `0x08` | User Data 是否加密 |
| C | `0x04` | 算法是否改写了 User Data |
| AN | `0x03` | SA 编号 0–3，换 SAK 时递增 |

E/C 组合：

| E | C | 抓包含义 |
|---|---|---|
| 1 | 1 | 机密性 + 完整性（实验室 `macsec-lab-encrypted.pcap`） |
| 0 | 0 | 只完整性，载荷明文（`macsec-lab-integrity-only.pcap`） |
| 0 | 1 | 只完整性但算法改写了载荷（少见） |
| 1 | 0 | **非法** |

实验室点对点两种编码都有：

- **SC=1**：SCI 在 SecTAG 里（多成员 CA 的常规做法；点对点也可以）
- **ES=1, SC=0**：SCI 不出现，接收方用 `SA ‖ 00-01` 还原（点对点常见）

IV **永远**用完整 8 字节 SCI，即使线上没带。

## 3. SL 与 PN

- **SL**（低 6 bit）：Secure Data 长度 &lt; 48 时填该长度，否则 0。实验室 ICMP User Data = 40 字节，所以 SL=40。
- **PN**：32 bit 大端，抗重放。同一把 SAK 上 PN 不得重复；耗尽前必须换 SAK（否则 GCM nonce 复用）。

## 4. GCM-AES-128（Clause 14）

记号与 NIST SP 800-38D / IEEE 测试向量一致：

| 参数 | 构造 |
|---|---|
| K | 16 字节 SAK |
| IV | SCI (8) ‖ PN (4) → 96 bit |
| T | 16 字节 ICV |

**完整性（E=0,C=0）**

- A = DA ‖ SA ‖ SecTAG ‖ User Data
- P = 空
- Secure Data = User Data（不改）

**机密性（E=1,C=1，offset 0）**

- A = DA ‖ SA ‖ SecTAG
- P = User Data
- Secure Data = C

User Data = 原帧的 EtherType + 载荷（不含外层 DA/SA）。实验室里是 `08 00` + IPv4 ICMP。

## 5. 对照 IEEE 公布向量

`bn-randall-test-vectors-0511` 中 GCM-AES-128：

| 项 | 完整性 54B 原帧 | 机密性 60B 原帧 |
|---|---|---|
| TCI/AN | `0x22`（SC=1, AN=2, E=C=0） | `0x2E`（SC=1, AN=2, E=C=1） |
| Key | `AD7A2BD03EAC835A6F620FDCB506B345` | 同左 |
| ICV | `F09478A9B09007D06F46E9B6A1DA25DD` | `4F8D55E7D3F06FD5A13C0C29B9D5B880` |

`make test` 会把本仓库组出来的帧与上表 **逐字节比对**。

## 6. 和 IPsec ESP 的对照（方便一起学）

| | MACsec | ESP |
|---|---|---|
| 层 | 以太网（hop-by-hop） | IP（端到端或隧道） |
| 会话密钥 | SAK（MKA 分发） | 从 IKE 派生 |
| 序号 | PN（在 SecTAG） | Sequence Number |
| 完整性尾 | ICV | ICV / GCM tag |
| 标识通道 | SCI | SPI |

MACsec 不替代 TLS / IPsec；中间交换机看到的是 hop 上的密文，出对端 SecY 后又是明文以太帧。
