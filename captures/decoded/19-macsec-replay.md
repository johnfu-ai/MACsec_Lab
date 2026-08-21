# 逐帧解析 — `macsec-replay.pcap`

共 **9** 帧。每条消息包含：作用说明、偏移字段表、十六进制；MACsec 另附解密后的内层 IPv4/ICMP。

## 总览

| # | 长度 | SA → DA | 一句话 |
|---:|---:|---|---|
| 1 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B PN=1 — in order, accepted; window advances |
| 2 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B PN=2 — in order, accepted |
| 3 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B PN=3 — in order, accepted (remember this frame) |
| 4 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B PN=5 — PN=4 missing (lost/reordered); PN=5 accepted, window slides: floor is now PN=3 |
| 5 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B PN=4 arrives late — inside the window (floor=3 < 4 < next=6), accepted as reordered |
| 6 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | REPLAY of frame 3, byte-identical, ICV still verifies — DROPPED: PN=3 <= floor(3), below the replay window |
| 7 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B PN=6 — in order, accepted |
| 8 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | DUPLICATE of the previous frame — DROPPED: PN=6 already seen inside the window |
| 9 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B PN=7 — in order, accepted; the replay attempts never advanced the window |

## 帧 1 — A→B PN=1 — in order, accepted; window advances

**MACsec  PN=1  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：A→B PN=1 — in order, accepted; window advances
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

## 帧 2 — A→B PN=2 — in order, accepted

**MACsec  PN=2  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：A→B PN=2 — in order, accepted
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

## 帧 3 — A→B PN=3 — in order, accepted (remember this frame)

**MACsec  PN=3  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：A→B PN=3 — in order, accepted (remember this frame)
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

## 帧 4 — A→B PN=5 — PN=4 missing (lost/reordered); PN=5 accepted, window slides: floor is now PN=3

**MACsec  PN=5  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：A→B PN=5 — PN=4 missing (lost/reordered); PN=5 accepted, window slides: floor is now PN=3
- TCI `0x2c`：confidentiality+integrity；PN = `5`；SCI = `02000000000a0001`
- GCM IV = SCI‖PN = `02000000000a000100000005`
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
| 16 | 4 | `00000005` | PN (wire) | `5 (0x00000005)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `f2982b5c07a0087198ee89280512762b…44dc9bc8` | Secure Data | `f2982b5c07a0087198ee89280512762bd5d4c034a7889c196abeb82f8fdf85258db2158f44dc9bc8` | 密文 |
| 68 | 16 | `f3c7741805aa73bf66debe72c7e5a997` | MACsec ICV | `f3c7741805aa73bf66debe72c7e5a997` | GCM tag；校验 通过 |

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
| 24 | 2 | `f0b1` | ICMP Checksum | `f0b1` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `0005` | ICMP Sequence | `5` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 0a 0a 0a 00 14 08 00  f0 b1 42 42 00 05 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0b 02 00  00 00 00 0a 88 e5 2c 28  ..............,(
0010  00 00 00 05 02 00 00 00  00 0a 00 01 f2 98 2b 5c  ..............+\
0020  07 a0 08 71 98 ee 89 28  05 12 76 2b d5 d4 c0 34  ...q...(..v+...4
0030  a7 88 9c 19 6a be b8 2f  8f df 85 25 8d b2 15 8f  ....j../...%....
0040  44 dc 9b c8 f3 c7 74 18  05 aa 73 bf 66 de be 72  D.....t...s.f..r
0050  c7 e5 a9 97                                       ....
```

## 帧 5 — A→B PN=4 arrives late — inside the window (floor=3 < 4 < next=6), accepted as reordered

**MACsec  PN=4  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：A→B PN=4 arrives late — inside the window (floor=3 < 4 < next=6), accepted as reordered
- TCI `0x2c`：confidentiality+integrity；PN = `4`；SCI = `02000000000a0001`
- GCM IV = SCI‖PN = `02000000000a000100000004`
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
| 16 | 4 | `00000004` | PN (wire) | `4 (0x00000004)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `6343a47a997357bc8ec1a5ceece646e2…46a4e8af` | Secure Data | `6343a47a997357bc8ec1a5ceece646e294193b3dae3ba350fc73693343128ed5a50d205346a4e8af` | 密文 |
| 68 | 16 | `c287d74710e730751c724ccdb0c30b63` | MACsec ICV | `c287d74710e730751c724ccdb0c30b63` | GCM tag；校验 通过 |

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
| 24 | 2 | `f0b2` | ICMP Checksum | `f0b2` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `0004` | ICMP Sequence | `4` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 0a 0a 0a 00 14 08 00  f0 b2 42 42 00 04 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0b 02 00  00 00 00 0a 88 e5 2c 28  ..............,(
0010  00 00 00 04 02 00 00 00  00 0a 00 01 63 43 a4 7a  ............cC.z
0020  99 73 57 bc 8e c1 a5 ce  ec e6 46 e2 94 19 3b 3d  .sW.......F...;=
0030  ae 3b a3 50 fc 73 69 33  43 12 8e d5 a5 0d 20 53  .;.P.si3C..... S
0040  46 a4 e8 af c2 87 d7 47  10 e7 30 75 1c 72 4c cd  F......G..0u.rL.
0050  b0 c3 0b 63                                       ...c
```

## 帧 6 — REPLAY of frame 3, byte-identical, ICV still verifies — DROPPED: PN=3 <= floor(3), below the replay window

**MACsec  PN=3  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：REPLAY of frame 3, byte-identical, ICV still verifies — DROPPED: PN=3 <= floor(3), below the replay window
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

## 帧 7 — A→B PN=6 — in order, accepted

**MACsec  PN=6  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：A→B PN=6 — in order, accepted
- TCI `0x2c`：confidentiality+integrity；PN = `6`；SCI = `02000000000a0001`
- GCM IV = SCI‖PN = `02000000000a000100000006`
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
| 16 | 4 | `00000006` | PN (wire) | `6 (0x00000006)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `88a647bda84a21277f85693f816ab8a3…93a02baf` | Secure Data | `88a647bda84a21277f85693f816ab8a3f27ed32ec96c4ee27685cc3ba7b8132bf58e23fe93a02baf` | 密文 |
| 68 | 16 | `62adc6b3b9b2d10ff784aad84155d155` | MACsec ICV | `62adc6b3b9b2d10ff784aad84155d155` | GCM tag；校验 通过 |

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
| 24 | 2 | `f0b0` | ICMP Checksum | `f0b0` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `0006` | ICMP Sequence | `6` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 0a 0a 0a 00 14 08 00  f0 b0 42 42 00 06 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0b 02 00  00 00 00 0a 88 e5 2c 28  ..............,(
0010  00 00 00 06 02 00 00 00  00 0a 00 01 88 a6 47 bd  ..............G.
0020  a8 4a 21 27 7f 85 69 3f  81 6a b8 a3 f2 7e d3 2e  .J!'..i?.j...~..
0030  c9 6c 4e e2 76 85 cc 3b  a7 b8 13 2b f5 8e 23 fe  .lN.v..;...+..#.
0040  93 a0 2b af 62 ad c6 b3  b9 b2 d1 0f f7 84 aa d8  ..+.b...........
0050  41 55 d1 55                                       AU.U
```

## 帧 8 — DUPLICATE of the previous frame — DROPPED: PN=6 already seen inside the window

**MACsec  PN=6  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：DUPLICATE of the previous frame — DROPPED: PN=6 already seen inside the window
- TCI `0x2c`：confidentiality+integrity；PN = `6`；SCI = `02000000000a0001`
- GCM IV = SCI‖PN = `02000000000a000100000006`
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
| 16 | 4 | `00000006` | PN (wire) | `6 (0x00000006)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `88a647bda84a21277f85693f816ab8a3…93a02baf` | Secure Data | `88a647bda84a21277f85693f816ab8a3f27ed32ec96c4ee27685cc3ba7b8132bf58e23fe93a02baf` | 密文 |
| 68 | 16 | `62adc6b3b9b2d10ff784aad84155d155` | MACsec ICV | `62adc6b3b9b2d10ff784aad84155d155` | GCM tag；校验 通过 |

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
| 24 | 2 | `f0b0` | ICMP Checksum | `f0b0` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `0006` | ICMP Sequence | `6` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 0a 0a 0a 00 14 08 00  f0 b0 42 42 00 06 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0b 02 00  00 00 00 0a 88 e5 2c 28  ..............,(
0010  00 00 00 06 02 00 00 00  00 0a 00 01 88 a6 47 bd  ..............G.
0020  a8 4a 21 27 7f 85 69 3f  81 6a b8 a3 f2 7e d3 2e  .J!'..i?.j...~..
0030  c9 6c 4e e2 76 85 cc 3b  a7 b8 13 2b f5 8e 23 fe  .lN.v..;...+..#.
0040  93 a0 2b af 62 ad c6 b3  b9 b2 d1 0f f7 84 aa d8  ..+.b...........
0050  41 55 d1 55                                       AU.U
```

## 帧 9 — A→B PN=7 — in order, accepted; the replay attempts never advanced the window

**MACsec  PN=7  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：A→B PN=7 — in order, accepted; the replay attempts never advanced the window
- TCI `0x2c`：confidentiality+integrity；PN = `7`；SCI = `02000000000a0001`
- GCM IV = SCI‖PN = `02000000000a000100000007`
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
| 16 | 4 | `00000007` | PN (wire) | `7 (0x00000007)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `0f2b22c04347988e2cc4f46ea8a91fc3…6598f234` | Secure Data | `0f2b22c04347988e2cc4f46ea8a91fc31fa13d31894e780055cc07ab1f30896dbee9291c6598f234` | 密文 |
| 68 | 16 | `d98c727ebf6a3de94e8fe4745c004f33` | MACsec ICV | `d98c727ebf6a3de94e8fe4745c004f33` | GCM tag；校验 通过 |

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
| 24 | 2 | `f0af` | ICMP Checksum | `f0af` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `0007` | ICMP Sequence | `7` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 0a 0a 0a 00 14 08 00  f0 af 42 42 00 07 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0b 02 00  00 00 00 0a 88 e5 2c 28  ..............,(
0010  00 00 00 07 02 00 00 00  00 0a 00 01 0f 2b 22 c0  .............+".
0020  43 47 98 8e 2c c4 f4 6e  a8 a9 1f c3 1f a1 3d 31  CG..,..n......=1
0030  89 4e 78 00 55 cc 07 ab  1f 30 89 6d be e9 29 1c  .Nx.U....0.m..).
0040  65 98 f2 34 d9 8c 72 7e  bf 6a 3d e9 4e 8f e4 74  e..4..r~.j=.N..t
0050  5c 00 4f 33                                       \.O3
```
