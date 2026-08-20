# 逐帧解析 — `mka-xpn.pcap`

共 **6** 帧。每条消息包含：作用说明、偏移字段表、十六进制；MACsec 另附解密后的内层 IPv4/ICMP。

## 总览

| # | 长度 | SA → DA | 一句话 |
|---:|---:|---|---|
| 1 | 186 | `02:00:00:00:00:0a` → `01:80:c2:00:00:03` | A MN=9 (MKA version 3, 802.1X-2020) rekey to XPN suite: Distributed SAK#4 carries cipher suite 00-80-C2-00-01-00-00-03 (body length 36; default suite omits the ID, 28) |
| 2 | 146 | `02:00:00:00:00:0b` → `01:80:c2:00:00:03` | B MN=9 installed XPN SAK#4: SAK Use latest=AN3 tx+rx; peer-list byte now carries B's own SSCI LSB 0x01 (非 XPN 故事里是 0) |
| 3 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B PN64=0x1FFFFFFFF: the LAST frame of the first 2^32 epoch — a 32-bit suite would have to rekey here, XPN keeps going |
| 4 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B PN64=0x200000001: on-wire PN wrapped to 0x00000001; receiver recovers the high half from SA state (802.1AE 10.6), same SAK, no MKA churn |
| 5 | 84 | `02:00:00:00:00:0b` → `02:00:00:00:00:0a` | B→A PN64=0x100000003: own SA, own SSCI, own PN64 space — the nonce is per-SC |
| 6 | 146 | `02:00:00:00:00:0b` → `01:80:c2:00:00:03` | B MN=10 keepalive on the XPN SA: everything above 2^32 is business as usual |

## 帧 1 — A MN=9 (MKA version 3, 802.1X-2020) rekey to XPN suite: Distributed SAK#4 carries cipher suite 00-80-C2-00-01-00-00-03 (body length 36; default suite omits the ID, 28)

**EAPOL-MKA  MN=9  Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `01:80:c2:00:00:03`（186 B）
- 作用：A MN=9 (MKA version 3, 802.1X-2020) rekey to XPN suite: Distributed SAK#4 carries cipher suite 00-80-C2-00-01-00-00-03 (body length 36; default suite omits the ID, 28)
- Key Server 标志 = `True`，优先级 = `16`，MN = `9`
- ICV 校验 = `True`（AES-CMAC(ICK, DA‖SA‖0x888E‖EAPOL−ICV)）

### 逐字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `0180c2000003` | DA | `01:80:c2:00:00:03` | PAE 组播（MKA 必须用组地址） |
| 6 | 6 | `02000000000a` | SA | `02:00:00:00:00:0a` | 发送方 MAC |
| 12 | 2 | `888e` | EtherType | `0x888e` | 802.1X EAPOL |
| 14 | 1 | `03` | EAPOL Version | `3` | 3 = 802.1X-2010 |
| 15 | 1 | `05` | EAPOL Type | `5` | 5 = EAPOL-MKA（不是 6） |
| 16 | 2 | `00a8` | Packet Body Length | `168` | 含 ICV，不含以太网头 |
| 18 | 1 | `03` | MKA Version | `3` | Basic 第 1 字节是版本不是 type；2 = 802.1X-2010，3 = 802.1X-2020（XPN 的 KS SSCI 字段随 v3 出现） |
| 19 | 1 | `10` | Key Server Priority | `16` | 数值越小越优先 |
| 20 | 2 | `f02c` | KS/Desired/Cap + BodyLen | `0xf02c` | KS=1 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | MAC ‖ Port ID |
| 30 | 12 | `aa01aa02aa03aa04aa05aa06` | Actor MI | `aa01aa02aa03aa04aa05aa06` | 12 字节成员标识 |
| 42 | 4 | `00000009` | Actor MN | `9` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `4d41435345432d4c41422d434b4e3031` | CKN | `4d41435345432d4c41422d434b4e3031` | ASCII 'MACSEC-LAB-CKN01'，两端必须一致 |
| 66 | 1 | `04` | Param type | `4` | Distributed SAK |
| 67 | 1 | `c0` | AN + Conf. offset | `0xc0` | AN=3 offset_code=0 (→前 0 字节不加密) |
| 68 | 2 | `0024` | Body length | `36` | 28 = 默认 GCM-AES-128（省略套件 ID）；36 = 128-bit SAK + 套件 ID；52 = 256-bit SAK + 套件 ID |
| 70 | 4 | `00000004` | Key Number | `4` | 本把 SAK 的编号 |
| 74 | 8 | `0080c20001000003` | SAK Cipher Suite | `00:80:c2:00:01:00:00:03` | GCM-AES-XPN-128（64-bit PN，SSCI+Salt nonce） |
| 82 | 24 | `09b2ed804c991137eaa1ee1a3c3b93216ac36f5e6e68181f` | AES-KW(SAK) | `09b2ed804c991137eaa1ee1a3c3b93216ac36f5e6e68181f` | AES-KeyWrap(KEK, SAK)，24 B = 16 B SAK + 8 B wrap IV；解开 = e1e2e3e4e5e6e7e8e9eaebecedeeeff0 |
| 106 | 1 | `01` | Param type | `1` | Live Peer List |
| 107 | 1 | `02` | KS SSCI LSB | `0x02` | XPN：发送方 SC 的 SSCI 低位（默认分配：SCI 最大者 0x0001）；非 XPN 时为 0 |
| 108 | 2 | `0010` | Body length | `16` |  |
| 110 | 12 | `bb01bb02bb03bb04bb05bb06` | Peer 1 MI | `bb01bb02bb03bb04bb05bb06` | 对端成员标识 |
| 122 | 4 | `00000008` | Peer 1 MN | `8` | 对端已确认的报文号 |
| 126 | 1 | `03` | Param type | `3` | MACsec SAK Use |
| 127 | 1 | `e9` | Latest/Old AN tx rx | `0xe9` | Latest AN=3 tx=1 rx=0; Old AN=2 tx=0 rx=1 |
| 128 | 2 | `1028` | Plain/Delay + BodyLen | `1028` | plain_tx=0 plain_rx=0 delay_protect=1 body=40 |
| 130 | 12 | `aa01aa02aa03aa04aa05aa06` | Latest KS MI | `aa01aa02aa03aa04aa05aa06` | KI 的 MI 部分 |
| 142 | 4 | `00000004` | Latest KN | `4` | KI 的 Key Number |
| 146 | 4 | `00000001` | Latest lowest PN | `1` | 抗重放窗口下沿 |
| 150 | 12 | `aa01aa02aa03aa04aa05aa06` | Old KS MI | `aa01aa02aa03aa04aa05aa06` | 无旧钥时为 0 |
| 162 | 4 | `00000003` | Old KN | `3` |  |
| 166 | 4 | `00000001` | Old lowest PN | `1` |  |
| 170 | 16 | `2598de5b6071789a8c5297bfe7131a34` | MKA ICV | `2598de5b6071789a8c5297bfe7131a34` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0a 88 8e 03 05  ................
0010  00 a8 03 10 f0 2c 02 00  00 00 00 0a 00 01 aa 01  .....,..........
0020  aa 02 aa 03 aa 04 aa 05  aa 06 00 00 00 09 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 04 c0 00 24 00 00  00 04 00 80 c2 00 01 00  01...$..........
0050  00 03 09 b2 ed 80 4c 99  11 37 ea a1 ee 1a 3c 3b  ......L..7....<;
0060  93 21 6a c3 6f 5e 6e 68  18 1f 01 02 00 10 bb 01  .!j.o^nh........
0070  bb 02 bb 03 bb 04 bb 05  bb 06 00 00 00 08 03 e9  ................
0080  10 28 aa 01 aa 02 aa 03  aa 04 aa 05 aa 06 00 00  .(..............
0090  00 04 00 00 00 01 aa 01  aa 02 aa 03 aa 04 aa 05  ................
00a0  aa 06 00 00 00 03 00 00  00 01 25 98 de 5b 60 71  ..........%..[`q
00b0  78 9a 8c 52 97 bf e7 13  1a 34                    x..R.....4
```

## 帧 2 — B MN=9 installed XPN SAK#4: SAK Use latest=AN3 tx+rx; peer-list byte now carries B's own SSCI LSB 0x01 (非 XPN 故事里是 0)

**EAPOL-MKA  MN=9  非 Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `01:80:c2:00:00:03`（146 B）
- 作用：B MN=9 installed XPN SAK#4: SAK Use latest=AN3 tx+rx; peer-list byte now carries B's own SSCI LSB 0x01 (非 XPN 故事里是 0)
- Key Server 标志 = `False`，优先级 = `32`，MN = `9`
- ICV 校验 = `True`（AES-CMAC(ICK, DA‖SA‖0x888E‖EAPOL−ICV)）

### 逐字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `0180c2000003` | DA | `01:80:c2:00:00:03` | PAE 组播（MKA 必须用组地址） |
| 6 | 6 | `02000000000b` | SA | `02:00:00:00:00:0b` | 发送方 MAC |
| 12 | 2 | `888e` | EtherType | `0x888e` | 802.1X EAPOL |
| 14 | 1 | `03` | EAPOL Version | `3` | 3 = 802.1X-2010 |
| 15 | 1 | `05` | EAPOL Type | `5` | 5 = EAPOL-MKA（不是 6） |
| 16 | 2 | `0080` | Packet Body Length | `128` | 含 ICV，不含以太网头 |
| 18 | 1 | `03` | MKA Version | `3` | Basic 第 1 字节是版本不是 type；2 = 802.1X-2010，3 = 802.1X-2020（XPN 的 KS SSCI 字段随 v3 出现） |
| 19 | 1 | `20` | Key Server Priority | `32` | 数值越小越优先 |
| 20 | 2 | `702c` | KS/Desired/Cap + BodyLen | `0x702c` | KS=0 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | MAC ‖ Port ID |
| 30 | 12 | `bb01bb02bb03bb04bb05bb06` | Actor MI | `bb01bb02bb03bb04bb05bb06` | 12 字节成员标识 |
| 42 | 4 | `00000009` | Actor MN | `9` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `4d41435345432d4c41422d434b4e3031` | CKN | `4d41435345432d4c41422d434b4e3031` | ASCII 'MACSEC-LAB-CKN01'，两端必须一致 |
| 66 | 1 | `01` | Param type | `1` | Live Peer List |
| 67 | 1 | `01` | KS SSCI LSB | `0x01` | XPN：发送方 SC 的 SSCI 低位（默认分配：SCI 最大者 0x0001）；非 XPN 时为 0 |
| 68 | 2 | `0010` | Body length | `16` |  |
| 70 | 12 | `aa01aa02aa03aa04aa05aa06` | Peer 1 MI | `aa01aa02aa03aa04aa05aa06` | 对端成员标识 |
| 82 | 4 | `00000009` | Peer 1 MN | `9` | 对端已确认的报文号 |
| 86 | 1 | `03` | Param type | `3` | MACsec SAK Use |
| 87 | 1 | `f9` | Latest/Old AN tx rx | `0xf9` | Latest AN=3 tx=1 rx=1; Old AN=2 tx=0 rx=1 |
| 88 | 2 | `1028` | Plain/Delay + BodyLen | `1028` | plain_tx=0 plain_rx=0 delay_protect=1 body=40 |
| 90 | 12 | `aa01aa02aa03aa04aa05aa06` | Latest KS MI | `aa01aa02aa03aa04aa05aa06` | KI 的 MI 部分 |
| 102 | 4 | `00000004` | Latest KN | `4` | KI 的 Key Number |
| 106 | 4 | `00000001` | Latest lowest PN | `1` | 抗重放窗口下沿 |
| 110 | 12 | `aa01aa02aa03aa04aa05aa06` | Old KS MI | `aa01aa02aa03aa04aa05aa06` | 无旧钥时为 0 |
| 122 | 4 | `00000003` | Old KN | `3` |  |
| 126 | 4 | `00000001` | Old lowest PN | `1` |  |
| 130 | 16 | `5f11a39e135145fbbf3674c18126c9f2` | MKA ICV | `5f11a39e135145fbbf3674c18126c9f2` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0b 88 8e 03 05  ................
0010  00 80 03 20 70 2c 02 00  00 00 00 0b 00 01 bb 01  ... p,..........
0020  bb 02 bb 03 bb 04 bb 05  bb 06 00 00 00 09 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 01 01 00 10 aa 01  aa 02 aa 03 aa 04 aa 05  01..............
0050  aa 06 00 00 00 09 03 f9  10 28 aa 01 aa 02 aa 03  .........(......
0060  aa 04 aa 05 aa 06 00 00  00 04 00 00 00 01 aa 01  ................
0070  aa 02 aa 03 aa 04 aa 05  aa 06 00 00 00 03 00 00  ................
0080  00 01 5f 11 a3 9e 13 51  45 fb bf 36 74 c1 81 26  .._....QE..6t..&
0090  c9 f2                                             ..
```

## 帧 3 — A→B PN64=0x1FFFFFFFF: the LAST frame of the first 2^32 epoch — a 32-bit suite would have to rekey here, XPN keeps going

**MACsec  PN=4294967295  XPN PN64=0x1FFFFFFFF  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：A→B PN64=0x1FFFFFFFF: the LAST frame of the first 2^32 epoch — a 32-bit suite would have to rekey here, XPN keeps going
- TCI `0x2f`：confidentiality+integrity；PN = `4294967295`；SCI = `02000000000a0001`
- XPN IV = (SSCI‖PN64)⊕Salt = `020a000302000001fff5fffe`（SSCI=0x0002，PN64=0x00000001FFFFFFFF，Salt=`020a000102000000000a0001`）
- AAD = DA‖SA‖SecTAG（P = User Data）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000b` | DA | `02:00:00:00:00:0b` | 对端单播 MAC |
| 6 | 6 | `02000000000a` | SA | `02:00:00:00:00:0a` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `2f` | TCI/AN | `0x2f` | V=0 ES=0 SC=1 SCB=0 E=1 C=1 AN=3；模式 confidentiality+integrity |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `ffffffff` | PN (wire) | `4294967295 (0xffffffff)` | XPN：线上只有低 32 位；高 32 位不在帧里（接收端恢复） |
| 16 | 0 | `` | PN64 (恢复) | `8589934591 (0x00000001ffffffff)` | 越过 2^32 后线上 PN 回绕，真实 PN 继续增长 |
| 16 | 0 | `` | SSCI | `0x0002` | 同 SAK 下每个 SC 唯一（默认：SCI 最大者 0x0001） |
| 16 | 0 | `` | Salt | `020a000102000000000a0001` | 公开 nonce 扰码，默认从 KS SCI 推导 |
| 20 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `4a55eda1978f25cc2af9a9ca4c008842…98676a02` | Secure Data | `4a55eda1978f25cc2af9a9ca4c0088423a6016cd9f5d29a6b800c7df098ac18211461a0698676a02` | 密文 |
| 68 | 16 | `47465acb962242ca33fdf9ec73b70089` | MACsec ICV | `47465acb962242ca33fdf9ec73b70089` | GCM tag；校验 通过 |

### 解密后 User Data（相对 User Data 起始）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 2 | `0800` | 原 EtherType | `0x0800` | 被保护的内层类型，不是 0x88E5 |
| 2 | 1 | `45` | IP Ver/IHL | `0x45` | IPv4, IHL=20 B |
| 3 | 1 | `00` | IP TOS | `0x00` |  |
| 4 | 2 | `0026` | IP Total Length | `38` | 含 IP 头 |
| 6 | 2 | `4242` | IP ID | `0x4242` |  |
| 8 | 2 | `0000` | IP Flags/Frag | `0000` |  |
| 10 | 1 | `40` | TTL | `64` |  |
| 11 | 1 | `01` | Protocol | `1` | 1 = ICMP |
| 12 | 2 | `2464` | IP Checksum | `2464` |  |
| 14 | 4 | `0a0a000a` | IP Src | `10.10.0.10` |  |
| 18 | 4 | `0a0a0014` | IP Dst | `10.10.0.20` |  |
| 22 | 1 | `08` | ICMP Type | `8` | Echo Request |
| 23 | 1 | `00` | ICMP Code | `0` |  |
| 24 | 2 | `f0a9` | ICMP Checksum | `f0a9` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `000d` | ICMP Sequence | `13` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 0a 0a 0a 00 14 08 00  f0 a9 42 42 00 0d 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0b 02 00  00 00 00 0a 88 e5 2f 28  ............../(
0010  ff ff ff ff 02 00 00 00  00 0a 00 01 4a 55 ed a1  ............JU..
0020  97 8f 25 cc 2a f9 a9 ca  4c 00 88 42 3a 60 16 cd  ..%.*...L..B:`..
0030  9f 5d 29 a6 b8 00 c7 df  09 8a c1 82 11 46 1a 06  .])..........F..
0040  98 67 6a 02 47 46 5a cb  96 22 42 ca 33 fd f9 ec  .gj.GFZ.."B.3...
0050  73 b7 00 89                                       s...
```

## 帧 4 — A→B PN64=0x200000001: on-wire PN wrapped to 0x00000001; receiver recovers the high half from SA state (802.1AE 10.6), same SAK, no MKA churn

**MACsec  PN=1  XPN PN64=0x200000001  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：A→B PN64=0x200000001: on-wire PN wrapped to 0x00000001; receiver recovers the high half from SA state (802.1AE 10.6), same SAK, no MKA churn
- TCI `0x2f`：confidentiality+integrity；PN = `1`；SCI = `02000000000a0001`
- XPN IV = (SSCI‖PN64)⊕Salt = `020a000302000002000a0000`（SSCI=0x0002，PN64=0x0000000200000001，Salt=`020a000102000000000a0001`）
- AAD = DA‖SA‖SecTAG（P = User Data）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000b` | DA | `02:00:00:00:00:0b` | 对端单播 MAC |
| 6 | 6 | `02000000000a` | SA | `02:00:00:00:00:0a` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `2f` | TCI/AN | `0x2f` | V=0 ES=0 SC=1 SCB=0 E=1 C=1 AN=3；模式 confidentiality+integrity |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `00000001` | PN (wire) | `1 (0x00000001)` | XPN：线上只有低 32 位；高 32 位不在帧里（接收端恢复） |
| 16 | 0 | `` | PN64 (恢复) | `8589934593 (0x0000000200000001)` | 越过 2^32 后线上 PN 回绕，真实 PN 继续增长 |
| 16 | 0 | `` | SSCI | `0x0002` | 同 SAK 下每个 SC 唯一（默认：SCI 最大者 0x0001） |
| 16 | 0 | `` | Salt | `020a000102000000000a0001` | 公开 nonce 扰码，默认从 KS SCI 推导 |
| 20 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `564bb7b6026231502ff30aff9feb0cc4…8510c020` | Secure Data | `564bb7b6026231502ff30aff9feb0cc4d29f7c7939f0ab160178ba1292d91461edb92e8e8510c020` | 密文 |
| 68 | 16 | `6115ff9d024158edf3a81a8ce58944d8` | MACsec ICV | `6115ff9d024158edf3a81a8ce58944d8` | GCM tag；校验 通过 |

### 解密后 User Data（相对 User Data 起始）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 2 | `0800` | 原 EtherType | `0x0800` | 被保护的内层类型，不是 0x88E5 |
| 2 | 1 | `45` | IP Ver/IHL | `0x45` | IPv4, IHL=20 B |
| 3 | 1 | `00` | IP TOS | `0x00` |  |
| 4 | 2 | `0026` | IP Total Length | `38` | 含 IP 头 |
| 6 | 2 | `4242` | IP ID | `0x4242` |  |
| 8 | 2 | `0000` | IP Flags/Frag | `0000` |  |
| 10 | 1 | `40` | TTL | `64` |  |
| 11 | 1 | `01` | Protocol | `1` | 1 = ICMP |
| 12 | 2 | `2464` | IP Checksum | `2464` |  |
| 14 | 4 | `0a0a000a` | IP Src | `10.10.0.10` |  |
| 18 | 4 | `0a0a0014` | IP Dst | `10.10.0.20` |  |
| 22 | 1 | `08` | ICMP Type | `8` | Echo Request |
| 23 | 1 | `00` | ICMP Code | `0` |  |
| 24 | 2 | `f0a8` | ICMP Checksum | `f0a8` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `000e` | ICMP Sequence | `14` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 0a 0a 0a 00 14 08 00  f0 a8 42 42 00 0e 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0b 02 00  00 00 00 0a 88 e5 2f 28  ............../(
0010  00 00 00 01 02 00 00 00  00 0a 00 01 56 4b b7 b6  ............VK..
0020  02 62 31 50 2f f3 0a ff  9f eb 0c c4 d2 9f 7c 79  .b1P/.........|y
0030  39 f0 ab 16 01 78 ba 12  92 d9 14 61 ed b9 2e 8e  9....x.....a....
0040  85 10 c0 20 61 15 ff 9d  02 41 58 ed f3 a8 1a 8c  ... a....AX.....
0050  e5 89 44 d8                                       ..D.
```

## 帧 5 — B→A PN64=0x100000003: own SA, own SSCI, own PN64 space — the nonce is per-SC

**MACsec  PN=3  XPN PN64=0x100000003  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `02:00:00:00:00:0a`（84 B）
- 作用：B→A PN64=0x100000003: own SA, own SSCI, own PN64 space — the nonce is per-SC
- TCI `0x2f`：confidentiality+integrity；PN = `3`；SCI = `02000000000b0001`
- XPN IV = (SSCI‖PN64)⊕Salt = `020a000002000001000a0002`（SSCI=0x0001，PN64=0x0000000100000003，Salt=`020a000102000000000a0001`）
- AAD = DA‖SA‖SecTAG（P = User Data）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000a` | DA | `02:00:00:00:00:0a` | 对端单播 MAC |
| 6 | 6 | `02000000000b` | SA | `02:00:00:00:00:0b` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `2f` | TCI/AN | `0x2f` | V=0 ES=0 SC=1 SCB=0 E=1 C=1 AN=3；模式 confidentiality+integrity |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `00000003` | PN (wire) | `3 (0x00000003)` | XPN：线上只有低 32 位；高 32 位不在帧里（接收端恢复） |
| 16 | 0 | `` | PN64 (恢复) | `4294967299 (0x0000000100000003)` | 越过 2^32 后线上 PN 回绕，真实 PN 继续增长 |
| 16 | 0 | `` | SSCI | `0x0001` | 同 SAK 下每个 SC 唯一（默认：SCI 最大者 0x0001） |
| 16 | 0 | `` | Salt | `020a000102000000000a0001` | 公开 nonce 扰码，默认从 KS SCI 推导 |
| 20 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `e84be88b764a9516c0467eb92b51ed48…f952e599` | Secure Data | `e84be88b764a9516c0467eb92b51ed48f9740b3e4a0529d4b7778c3b4ecdd4afd650df9cf952e599` | 密文 |
| 68 | 16 | `7439022cb703eee7bfc8d7c46d7e8d7c` | MACsec ICV | `7439022cb703eee7bfc8d7c46d7e8d7c` | GCM tag；校验 通过 |

### 解密后 User Data（相对 User Data 起始）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 2 | `0800` | 原 EtherType | `0x0800` | 被保护的内层类型，不是 0x88E5 |
| 2 | 1 | `45` | IP Ver/IHL | `0x45` | IPv4, IHL=20 B |
| 3 | 1 | `00` | IP TOS | `0x00` |  |
| 4 | 2 | `0026` | IP Total Length | `38` | 含 IP 头 |
| 6 | 2 | `4242` | IP ID | `0x4242` |  |
| 8 | 2 | `0000` | IP Flags/Frag | `0000` |  |
| 10 | 1 | `40` | TTL | `64` |  |
| 11 | 1 | `01` | Protocol | `1` | 1 = ICMP |
| 12 | 2 | `2464` | IP Checksum | `2464` |  |
| 14 | 4 | `0a0a0014` | IP Src | `10.10.0.20` |  |
| 18 | 4 | `0a0a000a` | IP Dst | `10.10.0.10` |  |
| 22 | 1 | `08` | ICMP Type | `8` | Echo Request |
| 23 | 1 | `00` | ICMP Code | `0` |  |
| 24 | 2 | `f0a7` | ICMP Checksum | `f0a7` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `000f` | ICMP Sequence | `15` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 14 0a 0a 00 0a 08 00  f0 a7 42 42 00 0f 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0a 02 00  00 00 00 0b 88 e5 2f 28  ............../(
0010  00 00 00 03 02 00 00 00  00 0b 00 01 e8 4b e8 8b  .............K..
0020  76 4a 95 16 c0 46 7e b9  2b 51 ed 48 f9 74 0b 3e  vJ...F~.+Q.H.t.>
0030  4a 05 29 d4 b7 77 8c 3b  4e cd d4 af d6 50 df 9c  J.)..w.;N....P..
0040  f9 52 e5 99 74 39 02 2c  b7 03 ee e7 bf c8 d7 c4  .R..t9.,........
0050  6d 7e 8d 7c                                       m~.|
```

## 帧 6 — B MN=10 keepalive on the XPN SA: everything above 2^32 is business as usual

**EAPOL-MKA  MN=10  非 Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `01:80:c2:00:00:03`（146 B）
- 作用：B MN=10 keepalive on the XPN SA: everything above 2^32 is business as usual
- Key Server 标志 = `False`，优先级 = `32`，MN = `10`
- ICV 校验 = `True`（AES-CMAC(ICK, DA‖SA‖0x888E‖EAPOL−ICV)）

### 逐字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `0180c2000003` | DA | `01:80:c2:00:00:03` | PAE 组播（MKA 必须用组地址） |
| 6 | 6 | `02000000000b` | SA | `02:00:00:00:00:0b` | 发送方 MAC |
| 12 | 2 | `888e` | EtherType | `0x888e` | 802.1X EAPOL |
| 14 | 1 | `03` | EAPOL Version | `3` | 3 = 802.1X-2010 |
| 15 | 1 | `05` | EAPOL Type | `5` | 5 = EAPOL-MKA（不是 6） |
| 16 | 2 | `0080` | Packet Body Length | `128` | 含 ICV，不含以太网头 |
| 18 | 1 | `03` | MKA Version | `3` | Basic 第 1 字节是版本不是 type；2 = 802.1X-2010，3 = 802.1X-2020（XPN 的 KS SSCI 字段随 v3 出现） |
| 19 | 1 | `20` | Key Server Priority | `32` | 数值越小越优先 |
| 20 | 2 | `702c` | KS/Desired/Cap + BodyLen | `0x702c` | KS=0 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | MAC ‖ Port ID |
| 30 | 12 | `bb01bb02bb03bb04bb05bb06` | Actor MI | `bb01bb02bb03bb04bb05bb06` | 12 字节成员标识 |
| 42 | 4 | `0000000a` | Actor MN | `10` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `4d41435345432d4c41422d434b4e3031` | CKN | `4d41435345432d4c41422d434b4e3031` | ASCII 'MACSEC-LAB-CKN01'，两端必须一致 |
| 66 | 1 | `01` | Param type | `1` | Live Peer List |
| 67 | 1 | `01` | KS SSCI LSB | `0x01` | XPN：发送方 SC 的 SSCI 低位（默认分配：SCI 最大者 0x0001）；非 XPN 时为 0 |
| 68 | 2 | `0010` | Body length | `16` |  |
| 70 | 12 | `aa01aa02aa03aa04aa05aa06` | Peer 1 MI | `aa01aa02aa03aa04aa05aa06` | 对端成员标识 |
| 82 | 4 | `00000009` | Peer 1 MN | `9` | 对端已确认的报文号 |
| 86 | 1 | `03` | Param type | `3` | MACsec SAK Use |
| 87 | 1 | `f0` | Latest/Old AN tx rx | `0xf0` | Latest AN=3 tx=1 rx=1; Old AN=0 tx=0 rx=0 |
| 88 | 2 | `1028` | Plain/Delay + BodyLen | `1028` | plain_tx=0 plain_rx=0 delay_protect=1 body=40 |
| 90 | 12 | `aa01aa02aa03aa04aa05aa06` | Latest KS MI | `aa01aa02aa03aa04aa05aa06` | KI 的 MI 部分 |
| 102 | 4 | `00000004` | Latest KN | `4` | KI 的 Key Number |
| 106 | 4 | `00000002` | Latest lowest PN | `2` | 抗重放窗口下沿 |
| 110 | 12 | `000000000000000000000000` | Old KS MI | `000000000000000000000000` | 无旧钥时为 0 |
| 122 | 4 | `00000000` | Old KN | `0` |  |
| 126 | 4 | `00000001` | Old lowest PN | `1` |  |
| 130 | 16 | `bad4edd088daac9b45073462e8836199` | MKA ICV | `bad4edd088daac9b45073462e8836199` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0b 88 8e 03 05  ................
0010  00 80 03 20 70 2c 02 00  00 00 00 0b 00 01 bb 01  ... p,..........
0020  bb 02 bb 03 bb 04 bb 05  bb 06 00 00 00 0a 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 01 01 00 10 aa 01  aa 02 aa 03 aa 04 aa 05  01..............
0050  aa 06 00 00 00 09 03 f0  10 28 aa 01 aa 02 aa 03  .........(......
0060  aa 04 aa 05 aa 06 00 00  00 04 00 00 00 02 00 00  ................
0070  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
0080  00 01 ba d4 ed d0 88 da  ac 9b 45 07 34 62 e8 83  ..........E.4b..
0090  61 99                                             a.
```
