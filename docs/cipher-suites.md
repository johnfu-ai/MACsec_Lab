# 密码套件：GCM-AES-128 / 256 / XPN

802.1AE-2018 一共定义了 **4 个**密码套件。它们的数据面格式完全相同（SecTAG、AAD、ICV 长度都不变），区别只有三处：**SAK 长度、nonce（IV）怎么构造、PN 多少位**。

| 套件 | Cipher Suite ID（8 字节） | SAK | PN | 引入 |
|---|---|---|---|---|
| **GCM-AES-128**（默认） | `00-80-C2-00-01-00-00-01` | 128 bit | 32 bit | 802.1AE-2006 |
| **GCM-AES-256** | `00-80-C2-00-01-00-00-02` | 256 bit | 32 bit | 802.1AEbn-2011 |
| **GCM-AES-XPN-128** | `00-80-C2-00-01-00-00-03` | 128 bit | **64 bit** | 802.1AEbw-2013 |
| **GCM-AES-XPN-256** | `00-80-C2-00-01-00-00-04` | 256 bit | **64 bit** | 802.1AEbw-2013 |

ICV 一律 128 bit（GCM tag）。四个套件的 AAD 构造（DA‖SA‖SecTAG‖…，含 confidentiality offset 变体）完全一致，见 [macsec-protocol-analysis.md](macsec-protocol-analysis.md)。

## 1. 套件怎么协商

- MKPDU Basic 里的 **Algorithm Agility**（`00-80-C2-01`）标识 KDF/ICV 算法族（AES-CMAC），不是数据面套件。
- 数据面套件随 SAK 分发：**Distributed SAK** 参数集里带 8 字节 cipher suite ID。**默认套件 GCM-AES-128 省略这个字段**（body length 28），其余三个套件都带（128-bit SAK 时 body length 36，256-bit SAK 时 52）——这就是为什么默认套件的 MKPDU 比别的短 8 字节。
- 双方能力在 Basic 的 MACsec Capability 里声明；最终用哪个套件由 **Key Server** 决定。

代码：`macsec_lab/keys.py` 的 `CS_GCM_AES_*`；`macsec_lab/mka.py` `DistributedSak(cipher_suite=...)`。

## 2. GCM-AES-256：换钥匙不换格式

256 套件只是把 K 从 16 字节换成 32 字节，nonce、AAD、ICV 全都不变。128 换 256 的动机是长期安全边际（量子后 128 bit 安全性打折的保守应对），不是性能——多数硬件上 256 略慢。

本仓库对 256 也有 **IEEE 公开向量逐字节验证**（Randall 2011 §2.1.2 完整性 / §2.2.2 机密性，同一帧、同一 IV、只换 256-bit key）：

| 项 | 128-bit | 256-bit |
|---|---|---|
| 完整性 ICV | `F09478A9…25DD` | `2F0BC5AF…EA50` |
| 机密性 ICV | `4F8D55E7…B880` | `5CA597CD…B436` |

抓包：`captures/macsec-ieee-gcm-aes-256-{integrity,encrypt}.pcap`（报告 15/16）。`make test` 逐字节比对两种长度。

## 3. XPN：64-bit PN（802.1AEbw-2013）

### 为什么需要

32-bit PN 在高速率下会**烧完**（见 [lifecycle.md](lifecycle.md) 的表：100G 小帧 ≈ 29 秒）。烧完前必须换 SAK，意味着控制面每几十秒折腾一轮。XPN 把 PN 扩到 64 bit，同时**帧格式一个字节都不改**：

- SecTAG 的 PN 字段**还是 32 bit**，装 64-bit PN 的**低 32 位**；
- 高 32 位不在帧里，由接收端从 SA 状态恢复（802.1AE 10.6：跟踪低 32 位回绕来推断高位）。

### nonce 怎么构造

默认套件的 IV 是 `SCI(64) ‖ PN(32)`。XPN 的 IV 换成 **SSCI + 64-bit PN 再整体 XOR 一个 Salt**：

```
IV(96) = ( SSCI(32) ‖ PN64(64) ) XOR Salt(96)
```

- **SSCI**（Short SCI，32 bit）：Key Server 经 MKA 分配的短标识，同一 SAK 下每个 SCI 唯一（默认按 SCI 大小排：最大的 SCI 用 0x0001，次之 0x0002…，两端无需信令即可算出一致结果）。它的 LSB 走 **Live Peer List 参数集**的第 2 字节（Wireshark 叫 "Key Server SSCI (LSB)"，按 802.1X-2020 11.11.3 与 XPN 套件一起出现，**MKA version 3** 才有——v2 的帧这个字节恒为 0）。
- **Salt**（96 bit）：随 SA 安装的nonce 扰码值。标准给了从 Key Server SCI 推导的默认值（`Salt[0:4] = SCI高32 XOR SCI低32`，`Salt[4:12] = KS的SCI`），部署上可当公开值——它的作用是让 nonce 与默认构造脱钩，**不是**第二把密钥。

抓包：`captures/mka-xpn.pcap`（报告 [17](../captures/decoded/17-mka-xpn.md)）把整条 XPN 故事走了一遍——

1. Key Server 分发 SAK#4 时 **Distributed SAK 带 8 字节套件 ID**（body 28 → 36，帧 1）；
2. Live Peer List 出现**非 0 的 KS SSCI LSB**（帧 1 是 A 的 0x02，帧 2/6 是 B 的 0x01）；
3. 数据面 **PN64 越过 2^32**：帧 3 线上 PN=0xFFFFFFFF，帧 4 回绕成 0x00000001（真实 PN64=0x2_00000001），**同一把 SAK 不换钥**——这正是 XPN 存在的意义（32-bit 套件到帧 3 就必须 rekey 了）；
4. 每帧的 IV 构造 `(SSCI‖PN64)⊕Salt` 在报告里逐字段展开，salt 取默认推导值。

tshark 注意：**4.7+** 才展开 36 字节 Distributed SAK 里的套件 ID；4.6 对该参数集显示 Undecoded（其余参数集正常）。KS SSCI 字段在 4.6 即可显示（要求 MKA version 3）。本仓库自带解析器不受版本影响。

代码：`macsec_lab/crypto.py` `xpn_iv(ssci, pn64, salt)`、`xpn_default_salt()`、`assign_sscis()`；`macsec_lab/macsec.py` `XpnPnTracker`（接收端按 802.1AE 10.6 从回绕恢复高 32 位）。测试验证了布局、salt 敏感性（salt 变一个字节 ICV 即失败）与 GCM 往返。标准 Annex C 有 XPN 向量，但公开渠道的草案文本里 ICV 留空（`???`），故本仓库对 XPN 只做构造级验证，**没有**逐字节向量——这是诚实声明，别把 XPN 测试当成向量验证。

### XPN 在哪用

25G/40G/100G+ 数据中心与运营商回传（高速率下 32-bit PN 真的不够）；Intel E810、Mellanox/NVIDIA ConnectX-6 及以后的 NIC 硬件同时支持四个套件。控制面 MKA 不变——CKN/CAK/KEK/ICK 仍按 [key-hierarchy.md](key-hierarchy.md) 派生。

## 4. 选择速查

| 场景 | 建议 |
|---|---|
| 普通企业/校园二层加密 | GCM-AES-128（默认，互操作性最好） |
| 合规要求更长密钥 | GCM-AES-256 |
| ≥25G 高速率 / 频繁 rekey 不可接受 | GCM-AES-XPN-128（常见默认） |
| 高速率 + 长密钥 | GCM-AES-XPN-256 |

注意：**两端和中间设备都要支持同一套件**。默认套件"永远在场"（802.1AE 强制实现），其余三个是可选（Optional）——对接前先确认对端能力，别只看标准存在就上。
