# MKA (IEEE 802.1X) 报文解析

MKA 跑在 **EAPOL** 上，目的 MAC 是 PAE 组地址 `01:80:c2:00:00:03`，EtherType `0x888E`。

参考抓包：`captures/mka-handshake.pcap`。

**每一帧的偏移级解析**（含 hex dump）：[protocol-analysis.md](protocol-analysis.md) 帧 1–6，或 [captures/decoded/01-mka-handshake.md](../captures/decoded/01-mka-handshake.md)。

## 1. EAPOL 头

```
[ DA ][ SA ][ 0x888E ][ Version=3 ][ Type=5 ][ Length ][ MKPDU ][ ICV 16 ]
```

| 字段 | 本实验室 |
|---|---|
| Version | 3（802.1X-2010） |
| **Packet Type** | **5 = EAPOL-MKA**（Table 11-3 编码 `0000 0101`） |
| Length | MKPDU 字节数（含 ICV） |

Type **6** 是 EAPOL-Announcement，不是 MKA。Wireshark 显示 `Type: MKA (5)`。

## 2. MKPDU 参数集

第一个参数集永远是 **Basic**（第 1 字节是 MKA 版本，不是 type）。其后按 type 编码，每集 4 字节头 + body，整体 4 字节对齐。最后 16 字节是 ICV（默认算法不必再带 ICV Indicator）。

实验室 6 帧：

| # | 发送方 | MN | 内容 |
|---|---|---|---|
| 1 | A | 1 | Basic，Key Server=1，还没有 peer |
| 2 | B | 1 | Basic，Key Server=0，**Potential Peer List** 含 A |
| 3 | A | 2 | **Distributed SAK** + **SAK Use (tx)** + **Live Peer List** |
| 4 | B | 2 | SAK Use **tx+rx** + Live（已安装 SAK） |
| 5 | A | 3 | 双方都 Use，会话起来 |
| 6 | B | 3 | keepalive |

### Basic Parameter Set（Figure 11-8）

| 字段 | 说明 |
|---|---|
| MKA Version | 本实验室 2 |
| Key Server Priority | **数值越小越优先**。A=16，B=32 → A 当选 |
| Key Server 标志 | 发送方认为自己是 / 将是 KS |
| MACsec Desired / Capability | Desired=1，Capability=3（完整机密性 + offset 0/30/50） |
| SCI | MAC ‖ Port ID |
| Actor MI | 12 字节随机成员标识 |
| Actor MN | 报文序号，每发一帧加一 |
| Algorithm Agility | `00-80-C2-01`（802.1X-2010 AES-CMAC） |
| CKN | 本实验室 ASCII `MACSEC-LAB-CKN01` |

Body length 是 12 bit，占用 octet 3 的低 4 bit + octet 4。Basic 固定部分 28 字节 + CKN；CKN=16 时 body length=44。

### Peer List（type 1 Live / type 2 Potential）

每项：MI (12) + MN (4)。Live 表示已双向看到、可参与 SAK；Potential 表示只听到过对方。

### Distributed SAK（type 4，GCM-AES-128）

| 字段 | 本实验室 |
|---|---|
| Distributed AN | 0 |
| Confidentiality Offset | 0 |
| Key Number | 1 |
| AES-KeyWrap(KEK, SAK) | 24 字节（16 字节 SAK + 8 字节 wrap IV） |

默认套件 GCM-AES-128 **不**再带 8 字节 Cipher Suite ID（body length=28）。其它套件走 Figure 11-12。

### SAK Use（type 3）

告诉对端：我是否已用 Latest/Old SAK 发送、接收。会话起来的标志是双方 Latest **tx 且 rx**。KI = Key Server MI ‖ Key Number。

## 3. 密钥派生（9.3 / 6.2.1）

KDF = NIST SP 800-108 计数器模式，PRF = AES-CMAC，label 恰好 12 字节：

```
KEK = KDF(CAK, "IEEE8021 KEK", CKN[0:16], 128)
ICK = KDF(CAK, "IEEE8021 ICK", CKN[0:16], 128)
```

演示值见 `captures/keys.json`（**公开，勿用于真实链路**）。

## 4. ICV（9.4.1）

```
ICV = AES-CMAC(ICK, M, 128)
M   = DA ‖ SA ‖ (MSDU − ICV)
    = DA ‖ SA ‖ 0x888E ‖ EAPOL头 ‖ 参数集
```

VLAN 等外层 tag **不算进** M。本解析器与 Wireshark `packet-mka.c` 的 `calculate_icv()` 一致。`decoded/01-mka-handshake.md` 里每帧 `ICV valid = True`。

在 Wireshark 里验 ICV：Preferences → Protocols → MKA → 填 CKN+CAK。

## 5. 选举规则（记）

1. Key Server Priority **数值越小越优先**。
2. 相同则 SCI 数值 **小者胜**。
3. 只有 KS 生成并分发 SAK；对端只安装。
