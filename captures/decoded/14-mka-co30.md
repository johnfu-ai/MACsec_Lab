# 逐帧解析 — `mka-co30.pcap`

共 **4** 帧。每条消息包含：作用说明、偏移字段表、十六进制；MACsec 另附解密后的内层 IPv4/ICMP。

## 总览

| # | 长度 | SA → DA | 一句话 |
|---:|---:|---|---|
| 1 | 178 | `02:00:00:00:00:0a` → `01:80:c2:00:00:03` | A MN=8: Distributed SAK#3 with confidentiality offset code 1 (=30 octets, AN=2 KN=3) |
| 2 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B data PN=1 AN=2 co=30 with SAK#3 — inner EtherType+IPv4+8 octets travel in clear (still ICV-protected), only the payload is encrypted |
| 3 | 84 | `02:00:00:00:00:0b` → `02:00:00:00:00:0a` | B→A data PN=1 AN=2 co=30 with SAK#3 — inner EtherType+IPv4+8 octets travel in clear (still ICV-protected), only the payload is encrypted |
| 4 | 146 | `02:00:00:00:00:0b` → `01:80:c2:00:00:03` | B MN=8 keepalive: SAK Use latest=AN2 tx+rx (installed SAK#3) |

## 帧 1 — A MN=8: Distributed SAK#3 with confidentiality offset code 1 (=30 octets, AN=2 KN=3)

**EAPOL-MKA  MN=8  Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `01:80:c2:00:00:03`（178 B）
- 作用：A MN=8: Distributed SAK#3 with confidentiality offset code 1 (=30 octets, AN=2 KN=3)
- Key Server 标志 = `True`，优先级 = `16`，MN = `8`
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
| 42 | 4 | `00000008` | Actor MN | `8` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `4d41435345432d4c41422d434b4e3031` | CKN | `4d41435345432d4c41422d434b4e3031` | ASCII 'MACSEC-LAB-CKN01'，两端必须一致 |
| 66 | 1 | `04` | Param type | `4` | Distributed SAK |
| 67 | 1 | `90` | AN + Conf. offset | `0x90` | AN=2 offset_code=1 (→前 30 字节不加密) |
| 68 | 2 | `001c` | Body length | `28` | 28 = 默认 GCM-AES-128 |
| 70 | 4 | `00000003` | Key Number | `3` | 本把 SAK 的编号 |
| 74 | 24 | `fac7884ef022741fbd851736103daa802d5d968a4b2ae651` | AES-KW(SAK) | `fac7884ef022741fbd851736103daa802d5d968a4b2ae651` | AES-KeyWrap(KEK, SAK)，24 B = 16 B SAK + 8 B wrap IV；解开 = d1d2d3d4d5d6d7d8d9dadbdcdddedfe0 |
| 98 | 1 | `01` | Param type | `1` | Live Peer List |
| 99 | 1 | `00` | KS SSCI LSB | `0` | 非 XPN 时为 0 |
| 100 | 2 | `0010` | Body length | `16` |  |
| 102 | 12 | `bb01bb02bb03bb04bb05bb06` | Peer 1 MI | `bb01bb02bb03bb04bb05bb06` | 对端成员标识 |
| 114 | 4 | `00000007` | Peer 1 MN | `7` | 对端已确认的报文号 |
| 118 | 1 | `03` | Param type | `3` | MACsec SAK Use |
| 119 | 1 | `a0` | Latest/Old AN tx rx | `0xa0` | Latest AN=2 tx=1 rx=0; Old AN=0 tx=0 rx=0 |
| 120 | 2 | `1028` | Plain/Delay + BodyLen | `1028` | plain_tx=0 plain_rx=0 delay_protect=1 body=40 |
| 122 | 12 | `aa01aa02aa03aa04aa05aa06` | Latest KS MI | `aa01aa02aa03aa04aa05aa06` | KI 的 MI 部分 |
| 134 | 4 | `00000003` | Latest KN | `3` | KI 的 Key Number |
| 138 | 4 | `00000001` | Latest lowest PN | `1` | 抗重放窗口下沿 |
| 142 | 12 | `000000000000000000000000` | Old KS MI | `000000000000000000000000` | 无旧钥时为 0 |
| 154 | 4 | `00000000` | Old KN | `0` |  |
| 158 | 4 | `00000001` | Old lowest PN | `1` |  |
| 162 | 16 | `730e9fe098e56df1ea8b3a422273d761` | MKA ICV | `730e9fe098e56df1ea8b3a422273d761` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0a 88 8e 03 05  ................
0010  00 a0 02 10 f0 2c 02 00  00 00 00 0a 00 01 aa 01  .....,..........
0020  aa 02 aa 03 aa 04 aa 05  aa 06 00 00 00 08 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 04 90 00 1c 00 00  00 03 fa c7 88 4e f0 22  01...........N."
0050  74 1f bd 85 17 36 10 3d  aa 80 2d 5d 96 8a 4b 2a  t....6.=..-]..K*
0060  e6 51 01 00 00 10 bb 01  bb 02 bb 03 bb 04 bb 05  .Q..............
0070  bb 06 00 00 00 07 03 a0  10 28 aa 01 aa 02 aa 03  .........(......
0080  aa 04 aa 05 aa 06 00 00  00 03 00 00 00 01 00 00  ................
0090  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00a0  00 01 73 0e 9f e0 98 e5  6d f1 ea 8b 3a 42 22 73  ..s.....m...:B"s
00b0  d7 61                                             .a
```

## 帧 2 — A→B data PN=1 AN=2 co=30 with SAK#3 — inner EtherType+IPv4+8 octets travel in clear (still ICV-protected), only the payload is encrypted

**MACsec  PN=1  confidentiality+integrity  co=30  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：A→B data PN=1 AN=2 co=30 with SAK#3 — inner EtherType+IPv4+8 octets travel in clear (still ICV-protected), only the payload is encrypted
- TCI `0x2e`：confidentiality+integrity（confidentiality offset 30，前 30 字节明文）；PN = `1`；SCI = `02000000000a0001`
- GCM IV = SCI‖PN = `02000000000a000100000001`
- AAD = DA‖SA‖SecTAG‖User[0:30]（P = User[30:]）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000b` | DA | `02:00:00:00:00:0b` | 对端单播 MAC |
| 6 | 6 | `02000000000a` | SA | `02:00:00:00:00:0a` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `2e` | TCI/AN | `0x2e` | V=0 ES=0 SC=1 SCB=0 E=1 C=1 AN=2；模式 confidentiality+integrity |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `00000001` | PN | `1 (0x00000001)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | 显式携带；IV 高 64 bit |
| 28 | 30 | `08004500002642420000400124640a0a…4242000c` | Secure Data 明文前缀 | `08004500002642420000400124640a0a000a0a0a00140800f0aa4242000c` | confidentiality offset 30：内层 EtherType+IP(+L4 头) 只认证、不加密 |
| 58 | 10 | `aaff1a1d515e85ed2771` | Secure Data 密文 | `aaff1a1d515e85ed2771` | User Data 第 30 字节起才是 GCM 明文 P |
| 68 | 16 | `33dfebaeb36f3ff74461ac2db43c232f` | MACsec ICV | `33dfebaeb36f3ff74461ac2db43c232f` | GCM tag；校验 通过 |

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
| 24 | 2 | `f0aa` | ICMP Checksum | `f0aa` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `000c` | ICMP Sequence | `12` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 0a 0a 0a 00 14 08 00  f0 aa 42 42 00 0c 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0b 02 00  00 00 00 0a 88 e5 2e 28  ...............(
0010  00 00 00 01 02 00 00 00  00 0a 00 01 08 00 45 00  ..............E.
0020  00 26 42 42 00 00 40 01  24 64 0a 0a 00 0a 0a 0a  .&BB..@.$d......
0030  00 14 08 00 f0 aa 42 42  00 0c aa ff 1a 1d 51 5e  ......BB......Q^
0040  85 ed 27 71 33 df eb ae  b3 6f 3f f7 44 61 ac 2d  ..'q3....o?.Da.-
0050  b4 3c 23 2f                                       .<#/
```

## 帧 3 — B→A data PN=1 AN=2 co=30 with SAK#3 — inner EtherType+IPv4+8 octets travel in clear (still ICV-protected), only the payload is encrypted

**MACsec  PN=1  confidentiality+integrity  co=30  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `02:00:00:00:00:0a`（84 B）
- 作用：B→A data PN=1 AN=2 co=30 with SAK#3 — inner EtherType+IPv4+8 octets travel in clear (still ICV-protected), only the payload is encrypted
- TCI `0x2e`：confidentiality+integrity（confidentiality offset 30，前 30 字节明文）；PN = `1`；SCI = `02000000000b0001`
- GCM IV = SCI‖PN = `02000000000b000100000001`
- AAD = DA‖SA‖SecTAG‖User[0:30]（P = User[30:]）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000a` | DA | `02:00:00:00:00:0a` | 对端单播 MAC |
| 6 | 6 | `02000000000b` | SA | `02:00:00:00:00:0b` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `2e` | TCI/AN | `0x2e` | V=0 ES=0 SC=1 SCB=0 E=1 C=1 AN=2；模式 confidentiality+integrity |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `00000001` | PN | `1 (0x00000001)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | 显式携带；IV 高 64 bit |
| 28 | 30 | `08004500002642420000400124640a0a…4242000c` | Secure Data 明文前缀 | `08004500002642420000400124640a0a00140a0a000a0800f0aa4242000c` | confidentiality offset 30：内层 EtherType+IP(+L4 头) 只认证、不加密 |
| 58 | 10 | `305b32ad4a431120afc1` | Secure Data 密文 | `305b32ad4a431120afc1` | User Data 第 30 字节起才是 GCM 明文 P |
| 68 | 16 | `05c671cbe4bb6f57e56eacc2e9a419e9` | MACsec ICV | `05c671cbe4bb6f57e56eacc2e9a419e9` | GCM tag；校验 通过 |

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
| 24 | 2 | `f0aa` | ICMP Checksum | `f0aa` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `000c` | ICMP Sequence | `12` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 14 0a 0a 00 0a 08 00  f0 aa 42 42 00 0c 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0a 02 00  00 00 00 0b 88 e5 2e 28  ...............(
0010  00 00 00 01 02 00 00 00  00 0b 00 01 08 00 45 00  ..............E.
0020  00 26 42 42 00 00 40 01  24 64 0a 0a 00 14 0a 0a  .&BB..@.$d......
0030  00 0a 08 00 f0 aa 42 42  00 0c 30 5b 32 ad 4a 43  ......BB..0[2.JC
0040  11 20 af c1 05 c6 71 cb  e4 bb 6f 57 e5 6e ac c2  . ....q...oW.n..
0050  e9 a4 19 e9                                       ....
```

## 帧 4 — B MN=8 keepalive: SAK Use latest=AN2 tx+rx (installed SAK#3)

**EAPOL-MKA  MN=8  非 Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `01:80:c2:00:00:03`（146 B）
- 作用：B MN=8 keepalive: SAK Use latest=AN2 tx+rx (installed SAK#3)
- Key Server 标志 = `False`，优先级 = `32`，MN = `8`
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
| 42 | 4 | `00000008` | Actor MN | `8` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `4d41435345432d4c41422d434b4e3031` | CKN | `4d41435345432d4c41422d434b4e3031` | ASCII 'MACSEC-LAB-CKN01'，两端必须一致 |
| 66 | 1 | `01` | Param type | `1` | Live Peer List |
| 67 | 1 | `00` | KS SSCI LSB | `0` | 非 XPN 时为 0 |
| 68 | 2 | `0010` | Body length | `16` |  |
| 70 | 12 | `aa01aa02aa03aa04aa05aa06` | Peer 1 MI | `aa01aa02aa03aa04aa05aa06` | 对端成员标识 |
| 82 | 4 | `00000008` | Peer 1 MN | `8` | 对端已确认的报文号 |
| 86 | 1 | `03` | Param type | `3` | MACsec SAK Use |
| 87 | 1 | `b0` | Latest/Old AN tx rx | `0xb0` | Latest AN=2 tx=1 rx=1; Old AN=0 tx=0 rx=0 |
| 88 | 2 | `1028` | Plain/Delay + BodyLen | `1028` | plain_tx=0 plain_rx=0 delay_protect=1 body=40 |
| 90 | 12 | `aa01aa02aa03aa04aa05aa06` | Latest KS MI | `aa01aa02aa03aa04aa05aa06` | KI 的 MI 部分 |
| 102 | 4 | `00000003` | Latest KN | `3` | KI 的 Key Number |
| 106 | 4 | `00000001` | Latest lowest PN | `1` | 抗重放窗口下沿 |
| 110 | 12 | `000000000000000000000000` | Old KS MI | `000000000000000000000000` | 无旧钥时为 0 |
| 122 | 4 | `00000000` | Old KN | `0` |  |
| 126 | 4 | `00000001` | Old lowest PN | `1` |  |
| 130 | 16 | `365ac01bc706224ef6e540b43c2c0f8c` | MKA ICV | `365ac01bc706224ef6e540b43c2c0f8c` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0b 88 8e 03 05  ................
0010  00 80 02 20 70 2c 02 00  00 00 00 0b 00 01 bb 01  ... p,..........
0020  bb 02 bb 03 bb 04 bb 05  bb 06 00 00 00 08 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 01 00 00 10 aa 01  aa 02 aa 03 aa 04 aa 05  01..............
0050  aa 06 00 00 00 08 03 b0  10 28 aa 01 aa 02 aa 03  .........(......
0060  aa 04 aa 05 aa 06 00 00  00 03 00 00 00 01 00 00  ................
0070  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
0080  00 01 36 5a c0 1b c7 06  22 4e f6 e5 40 b4 3c 2c  ..6Z...."N..@.<,
0090  0f 8c                                             ..
```
