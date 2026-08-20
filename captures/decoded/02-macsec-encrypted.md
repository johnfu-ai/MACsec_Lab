# 逐帧解析 — `macsec-lab-encrypted.pcap`

共 **7** 帧。每条消息包含：作用说明、偏移字段表、十六进制；MACsec 另附解密后的内层 IPv4/ICMP。

## 总览

| # | 长度 | SA → DA | 一句话 |
|---:|---:|---|---|
| 1 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B ICMP echo seq=1 (encrypted) |
| 2 | 84 | `02:00:00:00:00:0b` → `02:00:00:00:00:0a` | B→A ICMP seq=1 (encrypted) |
| 3 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B ICMP echo seq=2 (encrypted) |
| 4 | 84 | `02:00:00:00:00:0b` → `02:00:00:00:00:0a` | B→A ICMP seq=2 (encrypted) |
| 5 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B ICMP echo seq=3 (encrypted) |
| 6 | 84 | `02:00:00:00:00:0b` → `02:00:00:00:00:0a` | B→A ICMP seq=3 (encrypted) |
| 7 | 76 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B ES=1 no-SCI PN=9 (encrypted) |

## 帧 1 — A→B ICMP echo seq=1 (encrypted)

**MACsec  PN=1  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：A→B ICMP echo seq=1 (encrypted)
- TCI `0x2c`：confidentiality+integrity；PN = `1`；SCI = `02000000000a0001`
- GCM IV = SCI‖PN = `02000000000a000100000001`
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
| 16 | 4 | `00000001` | PN (wire) | `1 (0x00000001)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `459d7b17401a006c7e107e01f5bafef3…1c6ef164` | Secure Data | `459d7b17401a006c7e107e01f5bafef3eb307386a93c1bb6ca1f30c527e682a4d71abd541c6ef164` | 密文 |
| 68 | 16 | `c6aa63d5be322c44aa36d71502aa6ce9` | MACsec ICV | `c6aa63d5be322c44aa36d71502aa6ce9` | GCM tag；校验 通过 |

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
| 24 | 2 | `f0b5` | ICMP Checksum | `f0b5` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `0001` | ICMP Sequence | `1` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 0a 0a 0a 00 14 08 00  f0 b5 42 42 00 01 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0b 02 00  00 00 00 0a 88 e5 2c 28  ..............,(
0010  00 00 00 01 02 00 00 00  00 0a 00 01 45 9d 7b 17  ............E.{.
0020  40 1a 00 6c 7e 10 7e 01  f5 ba fe f3 eb 30 73 86  @..l~.~......0s.
0030  a9 3c 1b b6 ca 1f 30 c5  27 e6 82 a4 d7 1a bd 54  .<....0.'......T
0040  1c 6e f1 64 c6 aa 63 d5  be 32 2c 44 aa 36 d7 15  .n.d..c..2,D.6..
0050  02 aa 6c e9                                       ..l.
```

## 帧 2 — B→A ICMP seq=1 (encrypted)

**MACsec  PN=1  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `02:00:00:00:00:0a`（84 B）
- 作用：B→A ICMP seq=1 (encrypted)
- TCI `0x2c`：confidentiality+integrity；PN = `1`；SCI = `02000000000b0001`
- GCM IV = SCI‖PN = `02000000000b000100000001`
- AAD = DA‖SA‖SecTAG（P = User Data）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000a` | DA | `02:00:00:00:00:0a` | 对端单播 MAC |
| 6 | 6 | `02000000000b` | SA | `02:00:00:00:00:0b` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `2c` | TCI/AN | `0x2c` | V=0 ES=0 SC=1 SCB=0 E=1 C=1 AN=0；模式 confidentiality+integrity |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `00000001` | PN (wire) | `1 (0x00000001)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `26da7b83c51fa5cd01e3f3731e3cc5d8…5a2f65fa` | Secure Data | `26da7b83c51fa5cd01e3f3731e3cc5d88cb690717de9ad420554c1d4ae4f58ec877bfefa5a2f65fa` | 密文 |
| 68 | 16 | `2be0cf0800d7f1e84384aa27ee56ba7e` | MACsec ICV | `2be0cf0800d7f1e84384aa27ee56ba7e` | GCM tag；校验 通过 |

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
| 24 | 2 | `f0b5` | ICMP Checksum | `f0b5` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `0001` | ICMP Sequence | `1` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 14 0a 0a 00 0a 08 00  f0 b5 42 42 00 01 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0a 02 00  00 00 00 0b 88 e5 2c 28  ..............,(
0010  00 00 00 01 02 00 00 00  00 0b 00 01 26 da 7b 83  ............&.{.
0020  c5 1f a5 cd 01 e3 f3 73  1e 3c c5 d8 8c b6 90 71  .......s.<.....q
0030  7d e9 ad 42 05 54 c1 d4  ae 4f 58 ec 87 7b fe fa  }..B.T...OX..{..
0040  5a 2f 65 fa 2b e0 cf 08  00 d7 f1 e8 43 84 aa 27  Z/e.+.......C..'
0050  ee 56 ba 7e                                       .V.~
```

## 帧 3 — A→B ICMP echo seq=2 (encrypted)

**MACsec  PN=2  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：A→B ICMP echo seq=2 (encrypted)
- TCI `0x2c`：confidentiality+integrity；PN = `2`；SCI = `02000000000a0001`
- GCM IV = SCI‖PN = `02000000000a000100000002`
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
| 16 | 4 | `00000002` | PN (wire) | `2 (0x00000002)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `5ef76cf898540eef0505298be4eb4444…58e9cd7d` | Secure Data | `5ef76cf898540eef0505298be4eb44440d164d804d967186edf854626487dd06e897782958e9cd7d` | 密文 |
| 68 | 16 | `6d2fdc99866dd54a1b9272697011a29e` | MACsec ICV | `6d2fdc99866dd54a1b9272697011a29e` | GCM tag；校验 通过 |

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
| 24 | 2 | `f0b4` | ICMP Checksum | `f0b4` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `0002` | ICMP Sequence | `2` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 0a 0a 0a 00 14 08 00  f0 b4 42 42 00 02 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0b 02 00  00 00 00 0a 88 e5 2c 28  ..............,(
0010  00 00 00 02 02 00 00 00  00 0a 00 01 5e f7 6c f8  ............^.l.
0020  98 54 0e ef 05 05 29 8b  e4 eb 44 44 0d 16 4d 80  .T....)...DD..M.
0030  4d 96 71 86 ed f8 54 62  64 87 dd 06 e8 97 78 29  M.q...Tbd.....x)
0040  58 e9 cd 7d 6d 2f dc 99  86 6d d5 4a 1b 92 72 69  X..}m/...m.J..ri
0050  70 11 a2 9e                                       p...
```

## 帧 4 — B→A ICMP seq=2 (encrypted)

**MACsec  PN=2  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `02:00:00:00:00:0a`（84 B）
- 作用：B→A ICMP seq=2 (encrypted)
- TCI `0x2c`：confidentiality+integrity；PN = `2`；SCI = `02000000000b0001`
- GCM IV = SCI‖PN = `02000000000b000100000002`
- AAD = DA‖SA‖SecTAG（P = User Data）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000a` | DA | `02:00:00:00:00:0a` | 对端单播 MAC |
| 6 | 6 | `02000000000b` | SA | `02:00:00:00:00:0b` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `2c` | TCI/AN | `0x2c` | V=0 ES=0 SC=1 SCB=0 E=1 C=1 AN=0；模式 confidentiality+integrity |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `00000002` | PN (wire) | `2 (0x00000002)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `41450202619a88a30cf6520862215181…6978d079` | Secure Data | `41450202619a88a30cf6520862215181be1cb9ff57bb91132f8fa77eb949b225bf4b76256978d079` | 密文 |
| 68 | 16 | `c40c183451b3995fe380d946352bf4cc` | MACsec ICV | `c40c183451b3995fe380d946352bf4cc` | GCM tag；校验 通过 |

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
| 24 | 2 | `f0b4` | ICMP Checksum | `f0b4` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `0002` | ICMP Sequence | `2` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 14 0a 0a 00 0a 08 00  f0 b4 42 42 00 02 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0a 02 00  00 00 00 0b 88 e5 2c 28  ..............,(
0010  00 00 00 02 02 00 00 00  00 0b 00 01 41 45 02 02  ............AE..
0020  61 9a 88 a3 0c f6 52 08  62 21 51 81 be 1c b9 ff  a.....R.b!Q.....
0030  57 bb 91 13 2f 8f a7 7e  b9 49 b2 25 bf 4b 76 25  W.../..~.I.%.Kv%
0040  69 78 d0 79 c4 0c 18 34  51 b3 99 5f e3 80 d9 46  ix.y...4Q.._...F
0050  35 2b f4 cc                                       5+..
```

## 帧 5 — A→B ICMP echo seq=3 (encrypted)

**MACsec  PN=3  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：A→B ICMP echo seq=3 (encrypted)
- TCI `0x2c`：confidentiality+integrity；PN = `3`；SCI = `02000000000a0001`
- GCM IV = SCI‖PN = `02000000000a000100000003`
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
| 16 | 4 | `00000003` | PN (wire) | `3 (0x00000003)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `d417c6fc039b58e4a4b6b1dcb79a3009…ec0cd5ba` | Secure Data | `d417c6fc039b58e4a4b6b1dcb79a30091f3f450aac9b1908995efb2396e616052033b454ec0cd5ba` | 密文 |
| 68 | 16 | `219de9323bfc5a8cedd0f53168fe2c02` | MACsec ICV | `219de9323bfc5a8cedd0f53168fe2c02` | GCM tag；校验 通过 |

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
| 24 | 2 | `f0b3` | ICMP Checksum | `f0b3` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `0003` | ICMP Sequence | `3` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 0a 0a 0a 00 14 08 00  f0 b3 42 42 00 03 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0b 02 00  00 00 00 0a 88 e5 2c 28  ..............,(
0010  00 00 00 03 02 00 00 00  00 0a 00 01 d4 17 c6 fc  ................
0020  03 9b 58 e4 a4 b6 b1 dc  b7 9a 30 09 1f 3f 45 0a  ..X.......0..?E.
0030  ac 9b 19 08 99 5e fb 23  96 e6 16 05 20 33 b4 54  .....^.#.... 3.T
0040  ec 0c d5 ba 21 9d e9 32  3b fc 5a 8c ed d0 f5 31  ....!..2;.Z....1
0050  68 fe 2c 02                                       h.,.
```

## 帧 6 — B→A ICMP seq=3 (encrypted)

**MACsec  PN=3  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `02:00:00:00:00:0a`（84 B）
- 作用：B→A ICMP seq=3 (encrypted)
- TCI `0x2c`：confidentiality+integrity；PN = `3`；SCI = `02000000000b0001`
- GCM IV = SCI‖PN = `02000000000b000100000003`
- AAD = DA‖SA‖SecTAG（P = User Data）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000a` | DA | `02:00:00:00:00:0a` | 对端单播 MAC |
| 6 | 6 | `02000000000b` | SA | `02:00:00:00:00:0b` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `2c` | TCI/AN | `0x2c` | V=0 ES=0 SC=1 SCB=0 E=1 C=1 AN=0；模式 confidentiality+integrity |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `00000003` | PN (wire) | `3 (0x00000003)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `75285e94fd65792a5f82014042fe32d7…7cad325e` | Secure Data | `75285e94fd65792a5f82014042fe32d79b1f155fad0d1b3ecb1d4a6a6f1d8b228476a64f7cad325e` | 密文 |
| 68 | 16 | `a12157447fb8c2ed971bf20b3bf0ede7` | MACsec ICV | `a12157447fb8c2ed971bf20b3bf0ede7` | GCM tag；校验 通过 |

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
| 24 | 2 | `f0b3` | ICMP Checksum | `f0b3` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `0003` | ICMP Sequence | `3` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 14 0a 0a 00 0a 08 00  f0 b3 42 42 00 03 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0a 02 00  00 00 00 0b 88 e5 2c 28  ..............,(
0010  00 00 00 03 02 00 00 00  00 0b 00 01 75 28 5e 94  ............u(^.
0020  fd 65 79 2a 5f 82 01 40  42 fe 32 d7 9b 1f 15 5f  .ey*_..@B.2...._
0030  ad 0d 1b 3e cb 1d 4a 6a  6f 1d 8b 22 84 76 a6 4f  ...>..Jjo..".v.O
0040  7c ad 32 5e a1 21 57 44  7f b8 c2 ed 97 1b f2 0b  |.2^.!WD........
0050  3b f0 ed e7                                       ;...
```

## 帧 7 — A→B ES=1 no-SCI PN=9 (encrypted)

**MACsec  PN=9  confidentiality+integrity  ES=1 无 SCI  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（76 B）
- 作用：A→B ES=1 no-SCI PN=9 (encrypted)
- TCI `0x4c`：confidentiality+integrity；PN = `9`；SCI = `02000000000a0001`
- GCM IV = SCI‖PN = `02000000000a000100000009`
- AAD = DA‖SA‖SecTAG（P = User Data）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000b` | DA | `02:00:00:00:00:0b` | 对端单播 MAC |
| 6 | 6 | `02000000000a` | SA | `02:00:00:00:00:0a` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `4c` | TCI/AN | `0x4c` | V=0 ES=1 SC=0 SCB=0 E=1 C=1 AN=0；模式 confidentiality+integrity |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `00000009` | PN (wire) | `9 (0x00000009)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 0 | `02000000000a0001` | SCI (inferred) | `02000000000a0001` | 线上无 SCI；ES=1 时用 SA‖00-01 还原，仍参与 IV |
| 20 | 40 | `3394d9cae188f72ddab1839035759139…ecba009b` | Secure Data | `3394d9cae188f72ddab1839035759139e1c14cd7c5c79b86244dbbdd630969eb43dc9773ecba009b` | 密文 |
| 60 | 16 | `aeaa5a25d25f4ea4a91436d1b016cd0e` | MACsec ICV | `aeaa5a25d25f4ea4a91436d1b016cd0e` | GCM tag；校验 通过 |

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
| 24 | 2 | `f0ad` | ICMP Checksum | `f0ad` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `0009` | ICMP Sequence | `9` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 0a 0a 0a 00 14 08 00  f0 ad 42 42 00 09 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0b 02 00  00 00 00 0a 88 e5 4c 28  ..............L(
0010  00 00 00 09 33 94 d9 ca  e1 88 f7 2d da b1 83 90  ....3......-....
0020  35 75 91 39 e1 c1 4c d7  c5 c7 9b 86 24 4d bb dd  5u.9..L.....$M..
0030  63 09 69 eb 43 dc 97 73  ec ba 00 9b ae aa 5a 25  c.i.C..s......Z%
0040  d2 5f 4e a4 a9 14 36 d1  b0 16 cd 0e              ._N...6.....
```
