# 逐帧解析 — `macsec-lab-integrity-only.pcap`

共 **7** 帧。每条消息包含：作用说明、偏移字段表、十六进制；MACsec 另附解密后的内层 IPv4/ICMP。

## 总览

| # | 长度 | SA → DA | 一句话 |
|---:|---:|---|---|
| 1 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B ICMP echo seq=1 (integrity-only) |
| 2 | 84 | `02:00:00:00:00:0b` → `02:00:00:00:00:0a` | B→A ICMP seq=1 (integrity-only) |
| 3 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B ICMP echo seq=2 (integrity-only) |
| 4 | 84 | `02:00:00:00:00:0b` → `02:00:00:00:00:0a` | B→A ICMP seq=2 (integrity-only) |
| 5 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B ICMP echo seq=3 (integrity-only) |
| 6 | 84 | `02:00:00:00:00:0b` → `02:00:00:00:00:0a` | B→A ICMP seq=3 (integrity-only) |
| 7 | 76 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B ES=1 no-SCI PN=9 (integrity-only) |

## 帧 1 — A→B ICMP echo seq=1 (integrity-only)

**MACsec  PN=1  integrity-only  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：A→B ICMP echo seq=1 (integrity-only)
- TCI `0x20`：integrity-only；PN = `1`；SCI = `02000000000a0001`
- GCM IV = SCI‖PN = `02000000000a000100000001`
- AAD = DA‖SA‖SecTAG‖User Data（P 为空）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000b` | DA | `02:00:00:00:00:0b` | 对端单播 MAC |
| 6 | 6 | `02000000000a` | SA | `02:00:00:00:00:0a` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `20` | TCI/AN | `0x20` | V=0 ES=0 SC=1 SCB=0 E=0 C=0 AN=0；模式 integrity-only |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `00000001` | PN | `1 (0x00000001)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `08004500002642420000400124640a0a…2d6c6162` | Secure Data | `08004500002642420000400124640a0a000a0a0a00140800f0b5424200016d61637365632d6c6162` | 明文 User Data（仅完整性） |
| 68 | 16 | `d036e24918e159f44f07f69a131d28d4` | MACsec ICV | `d036e24918e159f44f07f69a131d28d4` | GCM tag；校验 通过 |

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
0000  02 00 00 00 00 0b 02 00  00 00 00 0a 88 e5 20 28  .............. (
0010  00 00 00 01 02 00 00 00  00 0a 00 01 08 00 45 00  ..............E.
0020  00 26 42 42 00 00 40 01  24 64 0a 0a 00 0a 0a 0a  .&BB..@.$d......
0030  00 14 08 00 f0 b5 42 42  00 01 6d 61 63 73 65 63  ......BB..macsec
0040  2d 6c 61 62 d0 36 e2 49  18 e1 59 f4 4f 07 f6 9a  -lab.6.I..Y.O...
0050  13 1d 28 d4                                       ..(.
```

## 帧 2 — B→A ICMP seq=1 (integrity-only)

**MACsec  PN=1  integrity-only  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `02:00:00:00:00:0a`（84 B）
- 作用：B→A ICMP seq=1 (integrity-only)
- TCI `0x20`：integrity-only；PN = `1`；SCI = `02000000000b0001`
- GCM IV = SCI‖PN = `02000000000b000100000001`
- AAD = DA‖SA‖SecTAG‖User Data（P 为空）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000a` | DA | `02:00:00:00:00:0a` | 对端单播 MAC |
| 6 | 6 | `02000000000b` | SA | `02:00:00:00:00:0b` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `20` | TCI/AN | `0x20` | V=0 ES=0 SC=1 SCB=0 E=0 C=0 AN=0；模式 integrity-only |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `00000001` | PN | `1 (0x00000001)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `08004500002642420000400124640a0a…2d6c6162` | Secure Data | `08004500002642420000400124640a0a00140a0a000a0800f0b5424200016d61637365632d6c6162` | 明文 User Data（仅完整性） |
| 68 | 16 | `af724d248d101b909ddd70241026776a` | MACsec ICV | `af724d248d101b909ddd70241026776a` | GCM tag；校验 通过 |

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
0000  02 00 00 00 00 0a 02 00  00 00 00 0b 88 e5 20 28  .............. (
0010  00 00 00 01 02 00 00 00  00 0b 00 01 08 00 45 00  ..............E.
0020  00 26 42 42 00 00 40 01  24 64 0a 0a 00 14 0a 0a  .&BB..@.$d......
0030  00 0a 08 00 f0 b5 42 42  00 01 6d 61 63 73 65 63  ......BB..macsec
0040  2d 6c 61 62 af 72 4d 24  8d 10 1b 90 9d dd 70 24  -lab.rM$......p$
0050  10 26 77 6a                                       .&wj
```

## 帧 3 — A→B ICMP echo seq=2 (integrity-only)

**MACsec  PN=2  integrity-only  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：A→B ICMP echo seq=2 (integrity-only)
- TCI `0x20`：integrity-only；PN = `2`；SCI = `02000000000a0001`
- GCM IV = SCI‖PN = `02000000000a000100000002`
- AAD = DA‖SA‖SecTAG‖User Data（P 为空）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000b` | DA | `02:00:00:00:00:0b` | 对端单播 MAC |
| 6 | 6 | `02000000000a` | SA | `02:00:00:00:00:0a` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `20` | TCI/AN | `0x20` | V=0 ES=0 SC=1 SCB=0 E=0 C=0 AN=0；模式 integrity-only |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `00000002` | PN | `2 (0x00000002)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `08004500002642420000400124640a0a…2d6c6162` | Secure Data | `08004500002642420000400124640a0a000a0a0a00140800f0b4424200026d61637365632d6c6162` | 明文 User Data（仅完整性） |
| 68 | 16 | `2c7e97a2142d074c829b8b87b505e40d` | MACsec ICV | `2c7e97a2142d074c829b8b87b505e40d` | GCM tag；校验 通过 |

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
0000  02 00 00 00 00 0b 02 00  00 00 00 0a 88 e5 20 28  .............. (
0010  00 00 00 02 02 00 00 00  00 0a 00 01 08 00 45 00  ..............E.
0020  00 26 42 42 00 00 40 01  24 64 0a 0a 00 0a 0a 0a  .&BB..@.$d......
0030  00 14 08 00 f0 b4 42 42  00 02 6d 61 63 73 65 63  ......BB..macsec
0040  2d 6c 61 62 2c 7e 97 a2  14 2d 07 4c 82 9b 8b 87  -lab,~...-.L....
0050  b5 05 e4 0d                                       ....
```

## 帧 4 — B→A ICMP seq=2 (integrity-only)

**MACsec  PN=2  integrity-only  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `02:00:00:00:00:0a`（84 B）
- 作用：B→A ICMP seq=2 (integrity-only)
- TCI `0x20`：integrity-only；PN = `2`；SCI = `02000000000b0001`
- GCM IV = SCI‖PN = `02000000000b000100000002`
- AAD = DA‖SA‖SecTAG‖User Data（P 为空）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000a` | DA | `02:00:00:00:00:0a` | 对端单播 MAC |
| 6 | 6 | `02000000000b` | SA | `02:00:00:00:00:0b` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `20` | TCI/AN | `0x20` | V=0 ES=0 SC=1 SCB=0 E=0 C=0 AN=0；模式 integrity-only |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `00000002` | PN | `2 (0x00000002)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `08004500002642420000400124640a0a…2d6c6162` | Secure Data | `08004500002642420000400124640a0a00140a0a000a0800f0b4424200026d61637365632d6c6162` | 明文 User Data（仅完整性） |
| 68 | 16 | `46accdc0a393a7ab6f544acb3cf5e885` | MACsec ICV | `46accdc0a393a7ab6f544acb3cf5e885` | GCM tag；校验 通过 |

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
0000  02 00 00 00 00 0a 02 00  00 00 00 0b 88 e5 20 28  .............. (
0010  00 00 00 02 02 00 00 00  00 0b 00 01 08 00 45 00  ..............E.
0020  00 26 42 42 00 00 40 01  24 64 0a 0a 00 14 0a 0a  .&BB..@.$d......
0030  00 0a 08 00 f0 b4 42 42  00 02 6d 61 63 73 65 63  ......BB..macsec
0040  2d 6c 61 62 46 ac cd c0  a3 93 a7 ab 6f 54 4a cb  -labF.......oTJ.
0050  3c f5 e8 85                                       <...
```

## 帧 5 — A→B ICMP echo seq=3 (integrity-only)

**MACsec  PN=3  integrity-only  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：A→B ICMP echo seq=3 (integrity-only)
- TCI `0x20`：integrity-only；PN = `3`；SCI = `02000000000a0001`
- GCM IV = SCI‖PN = `02000000000a000100000003`
- AAD = DA‖SA‖SecTAG‖User Data（P 为空）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000b` | DA | `02:00:00:00:00:0b` | 对端单播 MAC |
| 6 | 6 | `02000000000a` | SA | `02:00:00:00:00:0a` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `20` | TCI/AN | `0x20` | V=0 ES=0 SC=1 SCB=0 E=0 C=0 AN=0；模式 integrity-only |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `00000003` | PN | `3 (0x00000003)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `08004500002642420000400124640a0a…2d6c6162` | Secure Data | `08004500002642420000400124640a0a000a0a0a00140800f0b3424200036d61637365632d6c6162` | 明文 User Data（仅完整性） |
| 68 | 16 | `a8c96890e4d70b54d0455cb7f1427e72` | MACsec ICV | `a8c96890e4d70b54d0455cb7f1427e72` | GCM tag；校验 通过 |

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
0000  02 00 00 00 00 0b 02 00  00 00 00 0a 88 e5 20 28  .............. (
0010  00 00 00 03 02 00 00 00  00 0a 00 01 08 00 45 00  ..............E.
0020  00 26 42 42 00 00 40 01  24 64 0a 0a 00 0a 0a 0a  .&BB..@.$d......
0030  00 14 08 00 f0 b3 42 42  00 03 6d 61 63 73 65 63  ......BB..macsec
0040  2d 6c 61 62 a8 c9 68 90  e4 d7 0b 54 d0 45 5c b7  -lab..h....T.E\.
0050  f1 42 7e 72                                       .B~r
```

## 帧 6 — B→A ICMP seq=3 (integrity-only)

**MACsec  PN=3  integrity-only  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `02:00:00:00:00:0a`（84 B）
- 作用：B→A ICMP seq=3 (integrity-only)
- TCI `0x20`：integrity-only；PN = `3`；SCI = `02000000000b0001`
- GCM IV = SCI‖PN = `02000000000b000100000003`
- AAD = DA‖SA‖SecTAG‖User Data（P 为空）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000a` | DA | `02:00:00:00:00:0a` | 对端单播 MAC |
| 6 | 6 | `02000000000b` | SA | `02:00:00:00:00:0b` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `20` | TCI/AN | `0x20` | V=0 ES=0 SC=1 SCB=0 E=0 C=0 AN=0；模式 integrity-only |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `00000003` | PN | `3 (0x00000003)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `08004500002642420000400124640a0a…2d6c6162` | Secure Data | `08004500002642420000400124640a0a00140a0a000a0800f0b3424200036d61637365632d6c6162` | 明文 User Data（仅完整性） |
| 68 | 16 | `f70518ce5a647ddd5f16de7738a23ed0` | MACsec ICV | `f70518ce5a647ddd5f16de7738a23ed0` | GCM tag；校验 通过 |

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
0000  02 00 00 00 00 0a 02 00  00 00 00 0b 88 e5 20 28  .............. (
0010  00 00 00 03 02 00 00 00  00 0b 00 01 08 00 45 00  ..............E.
0020  00 26 42 42 00 00 40 01  24 64 0a 0a 00 14 0a 0a  .&BB..@.$d......
0030  00 0a 08 00 f0 b3 42 42  00 03 6d 61 63 73 65 63  ......BB..macsec
0040  2d 6c 61 62 f7 05 18 ce  5a 64 7d dd 5f 16 de 77  -lab....Zd}._..w
0050  38 a2 3e d0                                       8.>.
```

## 帧 7 — A→B ES=1 no-SCI PN=9 (integrity-only)

**MACsec  PN=9  integrity-only  ES=1 无 SCI  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（76 B）
- 作用：A→B ES=1 no-SCI PN=9 (integrity-only)
- TCI `0x40`：integrity-only；PN = `9`；SCI = `02000000000a0001`
- GCM IV = SCI‖PN = `02000000000a000100000009`
- AAD = DA‖SA‖SecTAG‖User Data（P 为空）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000b` | DA | `02:00:00:00:00:0b` | 对端单播 MAC |
| 6 | 6 | `02000000000a` | SA | `02:00:00:00:00:0a` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `40` | TCI/AN | `0x40` | V=0 ES=1 SC=0 SCB=0 E=0 C=0 AN=0；模式 integrity-only |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `00000009` | PN | `9 (0x00000009)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 0 | `02000000000a0001` | SCI (inferred) | `02000000000a0001` | 线上无 SCI；ES=1 时用 SA‖00-01 还原，仍参与 IV |
| 20 | 40 | `08004500002642420000400124640a0a…2d6c6162` | Secure Data | `08004500002642420000400124640a0a000a0a0a00140800f0ad424200096d61637365632d6c6162` | 明文 User Data（仅完整性） |
| 60 | 16 | `44491c66a84a92eeb261d8ff6c9f6a53` | MACsec ICV | `44491c66a84a92eeb261d8ff6c9f6a53` | GCM tag；校验 通过 |

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
0000  02 00 00 00 00 0b 02 00  00 00 00 0a 88 e5 40 28  ..............@(
0010  00 00 00 09 08 00 45 00  00 26 42 42 00 00 40 01  ......E..&BB..@.
0020  24 64 0a 0a 00 0a 0a 0a  00 14 08 00 f0 ad 42 42  $d............BB
0030  00 09 6d 61 63 73 65 63  2d 6c 61 62 44 49 1c 66  ..macsec-labDI.f
0040  a8 4a 92 ee b2 61 d8 ff  6c 9f 6a 53              .J...a..l.jS
```
