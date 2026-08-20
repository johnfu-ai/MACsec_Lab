# 逐帧解析 — `mka-rekey.pcap`

共 **9** 帧。每条消息包含：作用说明、偏移字段表、十六进制；MACsec 另附解密后的内层 IPv4/ICMP。

## 总览

| # | 长度 | SA → DA | 一句话 |
|---:|---:|---|---|
| 1 | 146 | `02:00:00:00:00:0a` → `01:80:c2:00:00:03` | A MN=4 keepalive on SAK#1 (steady state, AN=0 KN=1) |
| 2 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B data PN=10 AN=0 with SAK#1 (PN keeps climbing toward exhaustion) |
| 3 | 146 | `02:00:00:00:00:0b` → `01:80:c2:00:00:03` | B MN=4 keepalive on SAK#1 |
| 4 | 178 | `02:00:00:00:00:0a` → `01:80:c2:00:00:03` | A MN=5 rekey: Distributed SAK#2 (AN=1 KN=2) + SAK Use latest=AN1 tx / old=AN0 tx+rx |
| 5 | 146 | `02:00:00:00:00:0b` → `01:80:c2:00:00:03` | B MN=5 installed SAK#2: SAK Use latest=AN1 tx+rx / old=AN0 tx+rx |
| 6 | 146 | `02:00:00:00:00:0a` → `01:80:c2:00:00:03` | A MN=6 stopped tx on SAK#1: latest=AN1 tx+rx / old=AN0 rx-only (drain) |
| 7 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B data PN=1 AN=1 with SAK#2 — PN restarts at 1 (each direction is its own SA with a fresh replay window) |
| 8 | 84 | `02:00:00:00:00:0b` → `02:00:00:00:00:0a` | B→A data PN=1 AN=1 with SAK#2 — PN restarts at 1 (each direction is its own SA with a fresh replay window) |
| 9 | 146 | `02:00:00:00:00:0b` → `01:80:c2:00:00:03` | B MN=7 keepalive on SAK#2; old SA retired (old KN=0) |

## 帧 1 — A MN=4 keepalive on SAK#1 (steady state, AN=0 KN=1)

**EAPOL-MKA  MN=4  Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `01:80:c2:00:00:03`（146 B）
- 作用：A MN=4 keepalive on SAK#1 (steady state, AN=0 KN=1)
- Key Server 标志 = `True`，优先级 = `16`，MN = `4`
- ICV 校验 = `True`（AES-CMAC(ICK, DA‖SA‖0x888E‖EAPOL−ICV)）

### 逐字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `0180c2000003` | DA | `01:80:c2:00:00:03` | PAE 组播（MKA 必须用组地址） |
| 6 | 6 | `02000000000a` | SA | `02:00:00:00:00:0a` | 发送方 MAC |
| 12 | 2 | `888e` | EtherType | `0x888e` | 802.1X EAPOL |
| 14 | 1 | `03` | EAPOL Version | `3` | 3 = 802.1X-2010 |
| 15 | 1 | `05` | EAPOL Type | `5` | 5 = EAPOL-MKA（不是 6） |
| 16 | 2 | `0080` | Packet Body Length | `128` | 含 ICV，不含以太网头 |
| 18 | 1 | `02` | MKA Version | `2` | Basic 第 1 字节是版本不是 type |
| 19 | 1 | `10` | Key Server Priority | `16` | 数值越小越优先 |
| 20 | 2 | `f02c` | KS/Desired/Cap + BodyLen | `0xf02c` | KS=1 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | MAC ‖ Port ID |
| 30 | 12 | `aa01aa02aa03aa04aa05aa06` | Actor MI | `aa01aa02aa03aa04aa05aa06` | 12 字节成员标识 |
| 42 | 4 | `00000004` | Actor MN | `4` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `4d41435345432d4c41422d434b4e3031` | CKN | `4d41435345432d4c41422d434b4e3031` | ASCII 'MACSEC-LAB-CKN01'，两端必须一致 |
| 66 | 1 | `01` | Param type | `1` | Live Peer List |
| 67 | 1 | `00` | KS SSCI LSB | `0` | 非 XPN 时为 0 |
| 68 | 2 | `0010` | Body length | `16` |  |
| 70 | 12 | `bb01bb02bb03bb04bb05bb06` | Peer 1 MI | `bb01bb02bb03bb04bb05bb06` | 对端成员标识 |
| 82 | 4 | `00000003` | Peer 1 MN | `3` | 对端已确认的报文号 |
| 86 | 1 | `03` | Param type | `3` | MACsec SAK Use |
| 87 | 1 | `30` | Latest/Old AN tx rx | `0x30` | Latest AN=0 tx=1 rx=1; Old AN=0 tx=0 rx=0 |
| 88 | 2 | `1028` | Plain/Delay + BodyLen | `1028` | plain_tx=0 plain_rx=0 delay_protect=1 body=40 |
| 90 | 12 | `aa01aa02aa03aa04aa05aa06` | Latest KS MI | `aa01aa02aa03aa04aa05aa06` | KI 的 MI 部分 |
| 102 | 4 | `00000001` | Latest KN | `1` | KI 的 Key Number |
| 106 | 4 | `0000000a` | Latest lowest PN | `10` | 抗重放窗口下沿 |
| 110 | 12 | `000000000000000000000000` | Old KS MI | `000000000000000000000000` | 无旧钥时为 0 |
| 122 | 4 | `00000000` | Old KN | `0` |  |
| 126 | 4 | `00000001` | Old lowest PN | `1` |  |
| 130 | 16 | `b5800e5f8c7e242a32b1f0a570e247ba` | MKA ICV | `b5800e5f8c7e242a32b1f0a570e247ba` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0a 88 8e 03 05  ................
0010  00 80 02 10 f0 2c 02 00  00 00 00 0a 00 01 aa 01  .....,..........
0020  aa 02 aa 03 aa 04 aa 05  aa 06 00 00 00 04 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 01 00 00 10 bb 01  bb 02 bb 03 bb 04 bb 05  01..............
0050  bb 06 00 00 00 03 03 30  10 28 aa 01 aa 02 aa 03  .......0.(......
0060  aa 04 aa 05 aa 06 00 00  00 01 00 00 00 0a 00 00  ................
0070  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
0080  00 01 b5 80 0e 5f 8c 7e  24 2a 32 b1 f0 a5 70 e2  ....._.~$*2...p.
0090  47 ba                                             G.
```

## 帧 2 — A→B data PN=10 AN=0 with SAK#1 (PN keeps climbing toward exhaustion)

**MACsec  PN=10  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：A→B data PN=10 AN=0 with SAK#1 (PN keeps climbing toward exhaustion)
- TCI `0x2c`：confidentiality+integrity；PN = `10`；SCI = `02000000000a0001`
- GCM IV = SCI‖PN = `02000000000a00010000000a`
- AAD = DA‖SA‖SecTAG（P = User Data）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000b` | DA | `02:00:00:00:00:0b` | 对端单播 MAC |
| 6 | 6 | `02000000000a` | SA | `02:00:00:00:00:0a` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `2c` | TCI/AN | `0x2c` | V=0 ES=0 SC=1 SCB=0 E=1 C=1 AN=0；模式 confidentiality+integrity |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `0000000a` | PN | `10 (0x0000000a)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `253db5f2b65cb9a56448206a2aedf2f6…6f0b2eec` | Secure Data | `253db5f2b65cb9a56448206a2aedf2f6b81bb76e7d8c49850a2540f5e42ccd5c4da47b6b6f0b2eec` | 密文 |
| 68 | 16 | `96b2dfcb9e885107a15cee4cc488a30d` | MACsec ICV | `96b2dfcb9e885107a15cee4cc488a30d` | GCM tag；校验 通过 |

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
| 24 | 2 | `f0ac` | ICMP Checksum | `f0ac` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `000a` | ICMP Sequence | `10` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 0a 0a 0a 00 14 08 00  f0 ac 42 42 00 0a 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0b 02 00  00 00 00 0a 88 e5 2c 28  ..............,(
0010  00 00 00 0a 02 00 00 00  00 0a 00 01 25 3d b5 f2  ............%=..
0020  b6 5c b9 a5 64 48 20 6a  2a ed f2 f6 b8 1b b7 6e  .\..dH j*......n
0030  7d 8c 49 85 0a 25 40 f5  e4 2c cd 5c 4d a4 7b 6b  }.I..%@..,.\M.{k
0040  6f 0b 2e ec 96 b2 df cb  9e 88 51 07 a1 5c ee 4c  o.........Q..\.L
0050  c4 88 a3 0d                                       ....
```

## 帧 3 — B MN=4 keepalive on SAK#1

**EAPOL-MKA  MN=4  非 Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `01:80:c2:00:00:03`（146 B）
- 作用：B MN=4 keepalive on SAK#1
- Key Server 标志 = `False`，优先级 = `32`，MN = `4`
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
| 18 | 1 | `02` | MKA Version | `2` | Basic 第 1 字节是版本不是 type |
| 19 | 1 | `20` | Key Server Priority | `32` | 数值越小越优先 |
| 20 | 2 | `702c` | KS/Desired/Cap + BodyLen | `0x702c` | KS=0 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | MAC ‖ Port ID |
| 30 | 12 | `bb01bb02bb03bb04bb05bb06` | Actor MI | `bb01bb02bb03bb04bb05bb06` | 12 字节成员标识 |
| 42 | 4 | `00000004` | Actor MN | `4` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `4d41435345432d4c41422d434b4e3031` | CKN | `4d41435345432d4c41422d434b4e3031` | ASCII 'MACSEC-LAB-CKN01'，两端必须一致 |
| 66 | 1 | `01` | Param type | `1` | Live Peer List |
| 67 | 1 | `00` | KS SSCI LSB | `0` | 非 XPN 时为 0 |
| 68 | 2 | `0010` | Body length | `16` |  |
| 70 | 12 | `aa01aa02aa03aa04aa05aa06` | Peer 1 MI | `aa01aa02aa03aa04aa05aa06` | 对端成员标识 |
| 82 | 4 | `00000004` | Peer 1 MN | `4` | 对端已确认的报文号 |
| 86 | 1 | `03` | Param type | `3` | MACsec SAK Use |
| 87 | 1 | `30` | Latest/Old AN tx rx | `0x30` | Latest AN=0 tx=1 rx=1; Old AN=0 tx=0 rx=0 |
| 88 | 2 | `1028` | Plain/Delay + BodyLen | `1028` | plain_tx=0 plain_rx=0 delay_protect=1 body=40 |
| 90 | 12 | `aa01aa02aa03aa04aa05aa06` | Latest KS MI | `aa01aa02aa03aa04aa05aa06` | KI 的 MI 部分 |
| 102 | 4 | `00000001` | Latest KN | `1` | KI 的 Key Number |
| 106 | 4 | `0000000a` | Latest lowest PN | `10` | 抗重放窗口下沿 |
| 110 | 12 | `000000000000000000000000` | Old KS MI | `000000000000000000000000` | 无旧钥时为 0 |
| 122 | 4 | `00000000` | Old KN | `0` |  |
| 126 | 4 | `00000001` | Old lowest PN | `1` |  |
| 130 | 16 | `1ac39242d89e06328b923dda38bca8d6` | MKA ICV | `1ac39242d89e06328b923dda38bca8d6` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0b 88 8e 03 05  ................
0010  00 80 02 20 70 2c 02 00  00 00 00 0b 00 01 bb 01  ... p,..........
0020  bb 02 bb 03 bb 04 bb 05  bb 06 00 00 00 04 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 01 00 00 10 aa 01  aa 02 aa 03 aa 04 aa 05  01..............
0050  aa 06 00 00 00 04 03 30  10 28 aa 01 aa 02 aa 03  .......0.(......
0060  aa 04 aa 05 aa 06 00 00  00 01 00 00 00 0a 00 00  ................
0070  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
0080  00 01 1a c3 92 42 d8 9e  06 32 8b 92 3d da 38 bc  .....B...2..=.8.
0090  a8 d6                                             ..
```

## 帧 4 — A MN=5 rekey: Distributed SAK#2 (AN=1 KN=2) + SAK Use latest=AN1 tx / old=AN0 tx+rx

**EAPOL-MKA  MN=5  Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `01:80:c2:00:00:03`（178 B）
- 作用：A MN=5 rekey: Distributed SAK#2 (AN=1 KN=2) + SAK Use latest=AN1 tx / old=AN0 tx+rx
- Key Server 标志 = `True`，优先级 = `16`，MN = `5`
- ICV 校验 = `True`（AES-CMAC(ICK, DA‖SA‖0x888E‖EAPOL−ICV)）

### 逐字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `0180c2000003` | DA | `01:80:c2:00:00:03` | PAE 组播（MKA 必须用组地址） |
| 6 | 6 | `02000000000a` | SA | `02:00:00:00:00:0a` | 发送方 MAC |
| 12 | 2 | `888e` | EtherType | `0x888e` | 802.1X EAPOL |
| 14 | 1 | `03` | EAPOL Version | `3` | 3 = 802.1X-2010 |
| 15 | 1 | `05` | EAPOL Type | `5` | 5 = EAPOL-MKA（不是 6） |
| 16 | 2 | `00a0` | Packet Body Length | `160` | 含 ICV，不含以太网头 |
| 18 | 1 | `02` | MKA Version | `2` | Basic 第 1 字节是版本不是 type |
| 19 | 1 | `10` | Key Server Priority | `16` | 数值越小越优先 |
| 20 | 2 | `f02c` | KS/Desired/Cap + BodyLen | `0xf02c` | KS=1 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | MAC ‖ Port ID |
| 30 | 12 | `aa01aa02aa03aa04aa05aa06` | Actor MI | `aa01aa02aa03aa04aa05aa06` | 12 字节成员标识 |
| 42 | 4 | `00000005` | Actor MN | `5` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `4d41435345432d4c41422d434b4e3031` | CKN | `4d41435345432d4c41422d434b4e3031` | ASCII 'MACSEC-LAB-CKN01'，两端必须一致 |
| 66 | 1 | `04` | Param type | `4` | Distributed SAK |
| 67 | 1 | `40` | AN + Conf. offset | `0x40` | AN=1 offset_code=0 (0→0 字节) |
| 68 | 2 | `001c` | Body length | `28` | 28 = 默认 GCM-AES-128 |
| 70 | 4 | `00000002` | Key Number | `2` | 本把 SAK 的编号 |
| 74 | 24 | `8f150985f8b603f1249387d26283ef50c46b5c8ba42b141f` | AES-KW(SAK) | `8f150985f8b603f1249387d26283ef50c46b5c8ba42b141f` | AES-KeyWrap(KEK, SAK)，24 B = 16 B SAK + 8 B wrap IV；解开 = c1c2c3c4c5c6c7c8c9cacbcccdcecfd0 |
| 98 | 1 | `01` | Param type | `1` | Live Peer List |
| 99 | 1 | `00` | KS SSCI LSB | `0` | 非 XPN 时为 0 |
| 100 | 2 | `0010` | Body length | `16` |  |
| 102 | 12 | `bb01bb02bb03bb04bb05bb06` | Peer 1 MI | `bb01bb02bb03bb04bb05bb06` | 对端成员标识 |
| 114 | 4 | `00000004` | Peer 1 MN | `4` | 对端已确认的报文号 |
| 118 | 1 | `03` | Param type | `3` | MACsec SAK Use |
| 119 | 1 | `63` | Latest/Old AN tx rx | `0x63` | Latest AN=1 tx=1 rx=0; Old AN=0 tx=1 rx=1 |
| 120 | 2 | `1028` | Plain/Delay + BodyLen | `1028` | plain_tx=0 plain_rx=0 delay_protect=1 body=40 |
| 122 | 12 | `aa01aa02aa03aa04aa05aa06` | Latest KS MI | `aa01aa02aa03aa04aa05aa06` | KI 的 MI 部分 |
| 134 | 4 | `00000002` | Latest KN | `2` | KI 的 Key Number |
| 138 | 4 | `00000001` | Latest lowest PN | `1` | 抗重放窗口下沿 |
| 142 | 12 | `aa01aa02aa03aa04aa05aa06` | Old KS MI | `aa01aa02aa03aa04aa05aa06` | 无旧钥时为 0 |
| 154 | 4 | `00000001` | Old KN | `1` |  |
| 158 | 4 | `0000000a` | Old lowest PN | `10` |  |
| 162 | 16 | `f53e9942f6788bcabfb5e38081982537` | MKA ICV | `f53e9942f6788bcabfb5e38081982537` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0a 88 8e 03 05  ................
0010  00 a0 02 10 f0 2c 02 00  00 00 00 0a 00 01 aa 01  .....,..........
0020  aa 02 aa 03 aa 04 aa 05  aa 06 00 00 00 05 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 04 40 00 1c 00 00  00 02 8f 15 09 85 f8 b6  01.@............
0050  03 f1 24 93 87 d2 62 83  ef 50 c4 6b 5c 8b a4 2b  ..$...b..P.k\..+
0060  14 1f 01 00 00 10 bb 01  bb 02 bb 03 bb 04 bb 05  ................
0070  bb 06 00 00 00 04 03 63  10 28 aa 01 aa 02 aa 03  .......c.(......
0080  aa 04 aa 05 aa 06 00 00  00 02 00 00 00 01 aa 01  ................
0090  aa 02 aa 03 aa 04 aa 05  aa 06 00 00 00 01 00 00  ................
00a0  00 0a f5 3e 99 42 f6 78  8b ca bf b5 e3 80 81 98  ...>.B.x........
00b0  25 37                                             %7
```

## 帧 5 — B MN=5 installed SAK#2: SAK Use latest=AN1 tx+rx / old=AN0 tx+rx

**EAPOL-MKA  MN=5  非 Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `01:80:c2:00:00:03`（146 B）
- 作用：B MN=5 installed SAK#2: SAK Use latest=AN1 tx+rx / old=AN0 tx+rx
- Key Server 标志 = `False`，优先级 = `32`，MN = `5`
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
| 18 | 1 | `02` | MKA Version | `2` | Basic 第 1 字节是版本不是 type |
| 19 | 1 | `20` | Key Server Priority | `32` | 数值越小越优先 |
| 20 | 2 | `702c` | KS/Desired/Cap + BodyLen | `0x702c` | KS=0 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | MAC ‖ Port ID |
| 30 | 12 | `bb01bb02bb03bb04bb05bb06` | Actor MI | `bb01bb02bb03bb04bb05bb06` | 12 字节成员标识 |
| 42 | 4 | `00000005` | Actor MN | `5` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `4d41435345432d4c41422d434b4e3031` | CKN | `4d41435345432d4c41422d434b4e3031` | ASCII 'MACSEC-LAB-CKN01'，两端必须一致 |
| 66 | 1 | `01` | Param type | `1` | Live Peer List |
| 67 | 1 | `00` | KS SSCI LSB | `0` | 非 XPN 时为 0 |
| 68 | 2 | `0010` | Body length | `16` |  |
| 70 | 12 | `aa01aa02aa03aa04aa05aa06` | Peer 1 MI | `aa01aa02aa03aa04aa05aa06` | 对端成员标识 |
| 82 | 4 | `00000005` | Peer 1 MN | `5` | 对端已确认的报文号 |
| 86 | 1 | `03` | Param type | `3` | MACsec SAK Use |
| 87 | 1 | `73` | Latest/Old AN tx rx | `0x73` | Latest AN=1 tx=1 rx=1; Old AN=0 tx=1 rx=1 |
| 88 | 2 | `1028` | Plain/Delay + BodyLen | `1028` | plain_tx=0 plain_rx=0 delay_protect=1 body=40 |
| 90 | 12 | `aa01aa02aa03aa04aa05aa06` | Latest KS MI | `aa01aa02aa03aa04aa05aa06` | KI 的 MI 部分 |
| 102 | 4 | `00000002` | Latest KN | `2` | KI 的 Key Number |
| 106 | 4 | `00000001` | Latest lowest PN | `1` | 抗重放窗口下沿 |
| 110 | 12 | `aa01aa02aa03aa04aa05aa06` | Old KS MI | `aa01aa02aa03aa04aa05aa06` | 无旧钥时为 0 |
| 122 | 4 | `00000001` | Old KN | `1` |  |
| 126 | 4 | `0000000a` | Old lowest PN | `10` |  |
| 130 | 16 | `099b507767e666766b2517ab44ca700f` | MKA ICV | `099b507767e666766b2517ab44ca700f` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0b 88 8e 03 05  ................
0010  00 80 02 20 70 2c 02 00  00 00 00 0b 00 01 bb 01  ... p,..........
0020  bb 02 bb 03 bb 04 bb 05  bb 06 00 00 00 05 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 01 00 00 10 aa 01  aa 02 aa 03 aa 04 aa 05  01..............
0050  aa 06 00 00 00 05 03 73  10 28 aa 01 aa 02 aa 03  .......s.(......
0060  aa 04 aa 05 aa 06 00 00  00 02 00 00 00 01 aa 01  ................
0070  aa 02 aa 03 aa 04 aa 05  aa 06 00 00 00 01 00 00  ................
0080  00 0a 09 9b 50 77 67 e6  66 76 6b 25 17 ab 44 ca  ....Pwg.fvk%..D.
0090  70 0f                                             p.
```

## 帧 6 — A MN=6 stopped tx on SAK#1: latest=AN1 tx+rx / old=AN0 rx-only (drain)

**EAPOL-MKA  MN=6  Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `01:80:c2:00:00:03`（146 B）
- 作用：A MN=6 stopped tx on SAK#1: latest=AN1 tx+rx / old=AN0 rx-only (drain)
- Key Server 标志 = `True`，优先级 = `16`，MN = `6`
- ICV 校验 = `True`（AES-CMAC(ICK, DA‖SA‖0x888E‖EAPOL−ICV)）

### 逐字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `0180c2000003` | DA | `01:80:c2:00:00:03` | PAE 组播（MKA 必须用组地址） |
| 6 | 6 | `02000000000a` | SA | `02:00:00:00:00:0a` | 发送方 MAC |
| 12 | 2 | `888e` | EtherType | `0x888e` | 802.1X EAPOL |
| 14 | 1 | `03` | EAPOL Version | `3` | 3 = 802.1X-2010 |
| 15 | 1 | `05` | EAPOL Type | `5` | 5 = EAPOL-MKA（不是 6） |
| 16 | 2 | `0080` | Packet Body Length | `128` | 含 ICV，不含以太网头 |
| 18 | 1 | `02` | MKA Version | `2` | Basic 第 1 字节是版本不是 type |
| 19 | 1 | `10` | Key Server Priority | `16` | 数值越小越优先 |
| 20 | 2 | `f02c` | KS/Desired/Cap + BodyLen | `0xf02c` | KS=1 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | MAC ‖ Port ID |
| 30 | 12 | `aa01aa02aa03aa04aa05aa06` | Actor MI | `aa01aa02aa03aa04aa05aa06` | 12 字节成员标识 |
| 42 | 4 | `00000006` | Actor MN | `6` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `4d41435345432d4c41422d434b4e3031` | CKN | `4d41435345432d4c41422d434b4e3031` | ASCII 'MACSEC-LAB-CKN01'，两端必须一致 |
| 66 | 1 | `01` | Param type | `1` | Live Peer List |
| 67 | 1 | `00` | KS SSCI LSB | `0` | 非 XPN 时为 0 |
| 68 | 2 | `0010` | Body length | `16` |  |
| 70 | 12 | `bb01bb02bb03bb04bb05bb06` | Peer 1 MI | `bb01bb02bb03bb04bb05bb06` | 对端成员标识 |
| 82 | 4 | `00000005` | Peer 1 MN | `5` | 对端已确认的报文号 |
| 86 | 1 | `03` | Param type | `3` | MACsec SAK Use |
| 87 | 1 | `71` | Latest/Old AN tx rx | `0x71` | Latest AN=1 tx=1 rx=1; Old AN=0 tx=0 rx=1 |
| 88 | 2 | `1028` | Plain/Delay + BodyLen | `1028` | plain_tx=0 plain_rx=0 delay_protect=1 body=40 |
| 90 | 12 | `aa01aa02aa03aa04aa05aa06` | Latest KS MI | `aa01aa02aa03aa04aa05aa06` | KI 的 MI 部分 |
| 102 | 4 | `00000002` | Latest KN | `2` | KI 的 Key Number |
| 106 | 4 | `00000001` | Latest lowest PN | `1` | 抗重放窗口下沿 |
| 110 | 12 | `aa01aa02aa03aa04aa05aa06` | Old KS MI | `aa01aa02aa03aa04aa05aa06` | 无旧钥时为 0 |
| 122 | 4 | `00000001` | Old KN | `1` |  |
| 126 | 4 | `0000000a` | Old lowest PN | `10` |  |
| 130 | 16 | `931e43cddc9a7e9f4ec5e6194d55a81b` | MKA ICV | `931e43cddc9a7e9f4ec5e6194d55a81b` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0a 88 8e 03 05  ................
0010  00 80 02 10 f0 2c 02 00  00 00 00 0a 00 01 aa 01  .....,..........
0020  aa 02 aa 03 aa 04 aa 05  aa 06 00 00 00 06 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 01 00 00 10 bb 01  bb 02 bb 03 bb 04 bb 05  01..............
0050  bb 06 00 00 00 05 03 71  10 28 aa 01 aa 02 aa 03  .......q.(......
0060  aa 04 aa 05 aa 06 00 00  00 02 00 00 00 01 aa 01  ................
0070  aa 02 aa 03 aa 04 aa 05  aa 06 00 00 00 01 00 00  ................
0080  00 0a 93 1e 43 cd dc 9a  7e 9f 4e c5 e6 19 4d 55  ....C...~.N...MU
0090  a8 1b                                             ..
```

## 帧 7 — A→B data PN=1 AN=1 with SAK#2 — PN restarts at 1 (each direction is its own SA with a fresh replay window)

**MACsec  PN=1  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：A→B data PN=1 AN=1 with SAK#2 — PN restarts at 1 (each direction is its own SA with a fresh replay window)
- TCI `0x2d`：confidentiality+integrity；PN = `1`；SCI = `02000000000a0001`
- GCM IV = SCI‖PN = `02000000000a000100000001`
- AAD = DA‖SA‖SecTAG（P = User Data）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000b` | DA | `02:00:00:00:00:0b` | 对端单播 MAC |
| 6 | 6 | `02000000000a` | SA | `02:00:00:00:00:0a` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `2d` | TCI/AN | `0x2d` | V=0 ES=0 SC=1 SCB=0 E=1 C=1 AN=1；模式 confidentiality+integrity |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `00000001` | PN | `1 (0x00000001)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `14527e60ed93d984facf72cf2704dee1…91347377` | Secure Data | `14527e60ed93d984facf72cf2704dee1642a5b492adeae9378e035009cc5c97a59e63af991347377` | 密文 |
| 68 | 16 | `43669d89401e33ce945049885341c391` | MACsec ICV | `43669d89401e33ce945049885341c391` | GCM tag；校验 通过 |

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
| 24 | 2 | `f0ab` | ICMP Checksum | `f0ab` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `000b` | ICMP Sequence | `11` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 0a 0a 0a 00 14 08 00  f0 ab 42 42 00 0b 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0b 02 00  00 00 00 0a 88 e5 2d 28  ..............-(
0010  00 00 00 01 02 00 00 00  00 0a 00 01 14 52 7e 60  .............R~`
0020  ed 93 d9 84 fa cf 72 cf  27 04 de e1 64 2a 5b 49  ......r.'...d*[I
0030  2a de ae 93 78 e0 35 00  9c c5 c9 7a 59 e6 3a f9  *...x.5....zY.:.
0040  91 34 73 77 43 66 9d 89  40 1e 33 ce 94 50 49 88  .4swCf..@.3..PI.
0050  53 41 c3 91                                       SA..
```

## 帧 8 — B→A data PN=1 AN=1 with SAK#2 — PN restarts at 1 (each direction is its own SA with a fresh replay window)

**MACsec  PN=1  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `02:00:00:00:00:0a`（84 B）
- 作用：B→A data PN=1 AN=1 with SAK#2 — PN restarts at 1 (each direction is its own SA with a fresh replay window)
- TCI `0x2d`：confidentiality+integrity；PN = `1`；SCI = `02000000000b0001`
- GCM IV = SCI‖PN = `02000000000b000100000001`
- AAD = DA‖SA‖SecTAG（P = User Data）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000a` | DA | `02:00:00:00:00:0a` | 对端单播 MAC |
| 6 | 6 | `02000000000b` | SA | `02:00:00:00:00:0b` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `2d` | TCI/AN | `0x2d` | V=0 ES=0 SC=1 SCB=0 E=1 C=1 AN=1；模式 confidentiality+integrity |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `00000001` | PN | `1 (0x00000001)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `e04ad7d0e1e24e96bcedaeaf7e3b9fc3…c87ab9ca` | Secure Data | `e04ad7d0e1e24e96bcedaeaf7e3b9fc374763d6460dfe06f3e319640249cabe36d674a06c87ab9ca` | 密文 |
| 68 | 16 | `ff25a71f8895d78f6768af92fd9b3aad` | MACsec ICV | `ff25a71f8895d78f6768af92fd9b3aad` | GCM tag；校验 通过 |

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
| 24 | 2 | `f0ab` | ICMP Checksum | `f0ab` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `000b` | ICMP Sequence | `11` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 14 0a 0a 00 0a 08 00  f0 ab 42 42 00 0b 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0a 02 00  00 00 00 0b 88 e5 2d 28  ..............-(
0010  00 00 00 01 02 00 00 00  00 0b 00 01 e0 4a d7 d0  .............J..
0020  e1 e2 4e 96 bc ed ae af  7e 3b 9f c3 74 76 3d 64  ..N.....~;..tv=d
0030  60 df e0 6f 3e 31 96 40  24 9c ab e3 6d 67 4a 06  `..o>1.@$...mgJ.
0040  c8 7a b9 ca ff 25 a7 1f  88 95 d7 8f 67 68 af 92  .z...%......gh..
0050  fd 9b 3a ad                                       ..:.
```

## 帧 9 — B MN=7 keepalive on SAK#2; old SA retired (old KN=0)

**EAPOL-MKA  MN=7  非 Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `01:80:c2:00:00:03`（146 B）
- 作用：B MN=7 keepalive on SAK#2; old SA retired (old KN=0)
- Key Server 标志 = `False`，优先级 = `32`，MN = `7`
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
| 18 | 1 | `02` | MKA Version | `2` | Basic 第 1 字节是版本不是 type |
| 19 | 1 | `20` | Key Server Priority | `32` | 数值越小越优先 |
| 20 | 2 | `702c` | KS/Desired/Cap + BodyLen | `0x702c` | KS=0 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | MAC ‖ Port ID |
| 30 | 12 | `bb01bb02bb03bb04bb05bb06` | Actor MI | `bb01bb02bb03bb04bb05bb06` | 12 字节成员标识 |
| 42 | 4 | `00000007` | Actor MN | `7` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `4d41435345432d4c41422d434b4e3031` | CKN | `4d41435345432d4c41422d434b4e3031` | ASCII 'MACSEC-LAB-CKN01'，两端必须一致 |
| 66 | 1 | `01` | Param type | `1` | Live Peer List |
| 67 | 1 | `00` | KS SSCI LSB | `0` | 非 XPN 时为 0 |
| 68 | 2 | `0010` | Body length | `16` |  |
| 70 | 12 | `aa01aa02aa03aa04aa05aa06` | Peer 1 MI | `aa01aa02aa03aa04aa05aa06` | 对端成员标识 |
| 82 | 4 | `00000006` | Peer 1 MN | `6` | 对端已确认的报文号 |
| 86 | 1 | `03` | Param type | `3` | MACsec SAK Use |
| 87 | 1 | `70` | Latest/Old AN tx rx | `0x70` | Latest AN=1 tx=1 rx=1; Old AN=0 tx=0 rx=0 |
| 88 | 2 | `1028` | Plain/Delay + BodyLen | `1028` | plain_tx=0 plain_rx=0 delay_protect=1 body=40 |
| 90 | 12 | `aa01aa02aa03aa04aa05aa06` | Latest KS MI | `aa01aa02aa03aa04aa05aa06` | KI 的 MI 部分 |
| 102 | 4 | `00000002` | Latest KN | `2` | KI 的 Key Number |
| 106 | 4 | `00000002` | Latest lowest PN | `2` | 抗重放窗口下沿 |
| 110 | 12 | `000000000000000000000000` | Old KS MI | `000000000000000000000000` | 无旧钥时为 0 |
| 122 | 4 | `00000000` | Old KN | `0` |  |
| 126 | 4 | `00000001` | Old lowest PN | `1` |  |
| 130 | 16 | `32bc1c2edac5a1f4c9d93d5fd515e42a` | MKA ICV | `32bc1c2edac5a1f4c9d93d5fd515e42a` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0b 88 8e 03 05  ................
0010  00 80 02 20 70 2c 02 00  00 00 00 0b 00 01 bb 01  ... p,..........
0020  bb 02 bb 03 bb 04 bb 05  bb 06 00 00 00 07 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 01 00 00 10 aa 01  aa 02 aa 03 aa 04 aa 05  01..............
0050  aa 06 00 00 00 06 03 70  10 28 aa 01 aa 02 aa 03  .......p.(......
0060  aa 04 aa 05 aa 06 00 00  00 02 00 00 00 02 00 00  ................
0070  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
0080  00 01 32 bc 1c 2e da c5  a1 f4 c9 d9 3d 5f d5 15  ..2.........=_..
0090  e4 2a                                             .*
```
