# 逐帧解析 — `session-full.pcap`

共 **13** 帧。每条消息包含：作用说明、偏移字段表、十六进制；MACsec 另附解密后的内层 IPv4/ICMP。

## 总览

| # | 长度 | SA → DA | 一句话 |
|---:|---:|---|---|
| 1 | 82 | `02:00:00:00:00:0a` → `01:80:c2:00:00:03` | A MN=1 hello (claim Key Server, no peers yet) |
| 2 | 102 | `02:00:00:00:00:0b` → `01:80:c2:00:00:03` | B MN=1 hello (saw A; Potential Peer List; not Key Server) |
| 3 | 178 | `02:00:00:00:00:0a` → `01:80:c2:00:00:03` | A MN=2 Key Server: Live Peer List + Distributed SAK + SAK Use (tx) |
| 4 | 146 | `02:00:00:00:00:0b` → `01:80:c2:00:00:03` | B MN=2: Live Peer List + SAK Use (tx+rx) after installing SAK |
| 5 | 146 | `02:00:00:00:00:0a` → `01:80:c2:00:00:03` | A MN=3: both sides using SAK (tx+rx), session up |
| 6 | 146 | `02:00:00:00:00:0b` → `01:80:c2:00:00:03` | B MN=3 keepalive |
| 7 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B ICMP echo seq=1 (encrypted) |
| 8 | 84 | `02:00:00:00:00:0b` → `02:00:00:00:00:0a` | B→A ICMP seq=1 (encrypted) |
| 9 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B ICMP echo seq=2 (encrypted) |
| 10 | 84 | `02:00:00:00:00:0b` → `02:00:00:00:00:0a` | B→A ICMP seq=2 (encrypted) |
| 11 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B ICMP echo seq=3 (encrypted) |
| 12 | 84 | `02:00:00:00:00:0b` → `02:00:00:00:00:0a` | B→A ICMP seq=3 (encrypted) |
| 13 | 76 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B ES=1 no-SCI PN=9 (encrypted) |

## 帧 1 — A MN=1 hello (claim Key Server, no peers yet)

**EAPOL-MKA  MN=1  Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `01:80:c2:00:00:03`（82 B）
- 作用：A MN=1 hello (claim Key Server, no peers yet)
- Key Server 标志 = `True`，优先级 = `16`，MN = `1`
- ICV 校验 = `True`（AES-CMAC(ICK, DA‖SA‖0x888E‖EAPOL−ICV)）

### 逐字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `0180c2000003` | DA | `01:80:c2:00:00:03` | PAE 组播（MKA 必须用组地址） |
| 6 | 6 | `02000000000a` | SA | `02:00:00:00:00:0a` | 发送方 MAC |
| 12 | 2 | `888e` | EtherType | `0x888e` | 802.1X EAPOL |
| 14 | 1 | `03` | EAPOL Version | `3` | 3 = 802.1X-2010 |
| 15 | 1 | `05` | EAPOL Type | `5` | 5 = EAPOL-MKA（不是 6） |
| 16 | 2 | `0040` | Packet Body Length | `64` | 含 ICV，不含以太网头 |
| 18 | 1 | `02` | MKA Version | `2` | Basic 第 1 字节是版本不是 type；2 = 802.1X-2010，3 = 802.1X-2020（XPN 的 KS SSCI 字段随 v3 出现） |
| 19 | 1 | `10` | Key Server Priority | `16` | 数值越小越优先 |
| 20 | 2 | `f02c` | KS/Desired/Cap + BodyLen | `0xf02c` | KS=1 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | MAC ‖ Port ID |
| 30 | 12 | `aa01aa02aa03aa04aa05aa06` | Actor MI | `aa01aa02aa03aa04aa05aa06` | 12 字节成员标识 |
| 42 | 4 | `00000001` | Actor MN | `1` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `4d41435345432d4c41422d434b4e3031` | CKN | `4d41435345432d4c41422d434b4e3031` | ASCII 'MACSEC-LAB-CKN01'，两端必须一致 |
| 66 | 16 | `71216e851900b42b0f9d5797f8938f98` | MKA ICV | `71216e851900b42b0f9d5797f8938f98` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0a 88 8e 03 05  ................
0010  00 40 02 10 f0 2c 02 00  00 00 00 0a 00 01 aa 01  .@...,..........
0020  aa 02 aa 03 aa 04 aa 05  aa 06 00 00 00 01 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 71 21 6e 85 19 00  b4 2b 0f 9d 57 97 f8 93  01q!n....+..W...
0050  8f 98                                             ..
```

## 帧 2 — B MN=1 hello (saw A; Potential Peer List; not Key Server)

**EAPOL-MKA  MN=1  非 Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `01:80:c2:00:00:03`（102 B）
- 作用：B MN=1 hello (saw A; Potential Peer List; not Key Server)
- Key Server 标志 = `False`，优先级 = `32`，MN = `1`
- ICV 校验 = `True`（AES-CMAC(ICK, DA‖SA‖0x888E‖EAPOL−ICV)）

### 逐字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `0180c2000003` | DA | `01:80:c2:00:00:03` | PAE 组播（MKA 必须用组地址） |
| 6 | 6 | `02000000000b` | SA | `02:00:00:00:00:0b` | 发送方 MAC |
| 12 | 2 | `888e` | EtherType | `0x888e` | 802.1X EAPOL |
| 14 | 1 | `03` | EAPOL Version | `3` | 3 = 802.1X-2010 |
| 15 | 1 | `05` | EAPOL Type | `5` | 5 = EAPOL-MKA（不是 6） |
| 16 | 2 | `0054` | Packet Body Length | `84` | 含 ICV，不含以太网头 |
| 18 | 1 | `02` | MKA Version | `2` | Basic 第 1 字节是版本不是 type；2 = 802.1X-2010，3 = 802.1X-2020（XPN 的 KS SSCI 字段随 v3 出现） |
| 19 | 1 | `20` | Key Server Priority | `32` | 数值越小越优先 |
| 20 | 2 | `702c` | KS/Desired/Cap + BodyLen | `0x702c` | KS=0 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | MAC ‖ Port ID |
| 30 | 12 | `bb01bb02bb03bb04bb05bb06` | Actor MI | `bb01bb02bb03bb04bb05bb06` | 12 字节成员标识 |
| 42 | 4 | `00000001` | Actor MN | `1` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `4d41435345432d4c41422d434b4e3031` | CKN | `4d41435345432d4c41422d434b4e3031` | ASCII 'MACSEC-LAB-CKN01'，两端必须一致 |
| 66 | 1 | `02` | Param type | `2` | Potential Peer List |
| 67 | 1 | `00` | KS SSCI LSB | `0x00` | XPN：发送方 SC 的 SSCI 低位（默认分配：SCI 最大者 0x0001）；非 XPN 时为 0 |
| 68 | 2 | `0010` | Body length | `16` |  |
| 70 | 12 | `aa01aa02aa03aa04aa05aa06` | Peer 1 MI | `aa01aa02aa03aa04aa05aa06` | 对端成员标识 |
| 82 | 4 | `00000001` | Peer 1 MN | `1` | 对端已确认的报文号 |
| 86 | 16 | `05264f33c846a84cfe7ed916a10c537e` | MKA ICV | `05264f33c846a84cfe7ed916a10c537e` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0b 88 8e 03 05  ................
0010  00 54 02 20 70 2c 02 00  00 00 00 0b 00 01 bb 01  .T. p,..........
0020  bb 02 bb 03 bb 04 bb 05  bb 06 00 00 00 01 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 02 00 00 10 aa 01  aa 02 aa 03 aa 04 aa 05  01..............
0050  aa 06 00 00 00 01 05 26  4f 33 c8 46 a8 4c fe 7e  .......&O3.F.L.~
0060  d9 16 a1 0c 53 7e                                 ....S~
```

## 帧 3 — A MN=2 Key Server: Live Peer List + Distributed SAK + SAK Use (tx)

**EAPOL-MKA  MN=2  Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `01:80:c2:00:00:03`（178 B）
- 作用：A MN=2 Key Server: Live Peer List + Distributed SAK + SAK Use (tx)
- Key Server 标志 = `True`，优先级 = `16`，MN = `2`
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
| 18 | 1 | `02` | MKA Version | `2` | Basic 第 1 字节是版本不是 type；2 = 802.1X-2010，3 = 802.1X-2020（XPN 的 KS SSCI 字段随 v3 出现） |
| 19 | 1 | `10` | Key Server Priority | `16` | 数值越小越优先 |
| 20 | 2 | `f02c` | KS/Desired/Cap + BodyLen | `0xf02c` | KS=1 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | MAC ‖ Port ID |
| 30 | 12 | `aa01aa02aa03aa04aa05aa06` | Actor MI | `aa01aa02aa03aa04aa05aa06` | 12 字节成员标识 |
| 42 | 4 | `00000002` | Actor MN | `2` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `4d41435345432d4c41422d434b4e3031` | CKN | `4d41435345432d4c41422d434b4e3031` | ASCII 'MACSEC-LAB-CKN01'，两端必须一致 |
| 66 | 1 | `04` | Param type | `4` | Distributed SAK |
| 67 | 1 | `00` | AN + Conf. offset | `0x00` | AN=0 offset_code=0 (→前 0 字节不加密) |
| 68 | 2 | `001c` | Body length | `28` | 28 = 默认 GCM-AES-128（省略套件 ID）；36 = 128-bit SAK + 套件 ID；52 = 256-bit SAK + 套件 ID |
| 70 | 4 | `00000001` | Key Number | `1` | 本把 SAK 的编号 |
| 74 | 24 | `37f340ac59e7db5f164e8c830b35f671d8c583c19577ccd2` | AES-KW(SAK) | `37f340ac59e7db5f164e8c830b35f671d8c583c19577ccd2` | AES-KeyWrap(KEK, SAK)，24 B = 16 B SAK + 8 B wrap IV；解开 = a1a2a3a4a5a6a7a8a9aaabacadaeafb0 |
| 98 | 1 | `03` | Param type | `3` | MACsec SAK Use |
| 99 | 1 | `20` | Latest/Old AN tx rx | `0x20` | Latest AN=0 tx=1 rx=0; Old AN=0 tx=0 rx=0 |
| 100 | 2 | `1028` | Plain/Delay + BodyLen | `1028` | plain_tx=0 plain_rx=0 delay_protect=1 body=40 |
| 102 | 12 | `aa01aa02aa03aa04aa05aa06` | Latest KS MI | `aa01aa02aa03aa04aa05aa06` | KI 的 MI 部分 |
| 114 | 4 | `00000001` | Latest KN | `1` | KI 的 Key Number |
| 118 | 4 | `00000001` | Latest lowest PN | `1` | 抗重放窗口下沿 |
| 122 | 12 | `000000000000000000000000` | Old KS MI | `000000000000000000000000` | 无旧钥时为 0 |
| 134 | 4 | `00000000` | Old KN | `0` |  |
| 138 | 4 | `00000001` | Old lowest PN | `1` |  |
| 142 | 1 | `01` | Param type | `1` | Live Peer List |
| 143 | 1 | `00` | KS SSCI LSB | `0x00` | XPN：发送方 SC 的 SSCI 低位（默认分配：SCI 最大者 0x0001）；非 XPN 时为 0 |
| 144 | 2 | `0010` | Body length | `16` |  |
| 146 | 12 | `bb01bb02bb03bb04bb05bb06` | Peer 1 MI | `bb01bb02bb03bb04bb05bb06` | 对端成员标识 |
| 158 | 4 | `00000001` | Peer 1 MN | `1` | 对端已确认的报文号 |
| 162 | 16 | `057cf5d7eff30d762176bdbd5c269c98` | MKA ICV | `057cf5d7eff30d762176bdbd5c269c98` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0a 88 8e 03 05  ................
0010  00 a0 02 10 f0 2c 02 00  00 00 00 0a 00 01 aa 01  .....,..........
0020  aa 02 aa 03 aa 04 aa 05  aa 06 00 00 00 02 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 04 00 00 1c 00 00  00 01 37 f3 40 ac 59 e7  01........7.@.Y.
0050  db 5f 16 4e 8c 83 0b 35  f6 71 d8 c5 83 c1 95 77  ._.N...5.q.....w
0060  cc d2 03 20 10 28 aa 01  aa 02 aa 03 aa 04 aa 05  ... .(..........
0070  aa 06 00 00 00 01 00 00  00 01 00 00 00 00 00 00  ................
0080  00 00 00 00 00 00 00 00  00 00 00 00 00 01 01 00  ................
0090  00 10 bb 01 bb 02 bb 03  bb 04 bb 05 bb 06 00 00  ................
00a0  00 01 05 7c f5 d7 ef f3  0d 76 21 76 bd bd 5c 26  ...|.....v!v..\&
00b0  9c 98                                             ..
```

## 帧 4 — B MN=2: Live Peer List + SAK Use (tx+rx) after installing SAK

**EAPOL-MKA  MN=2  非 Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `01:80:c2:00:00:03`（146 B）
- 作用：B MN=2: Live Peer List + SAK Use (tx+rx) after installing SAK
- Key Server 标志 = `False`，优先级 = `32`，MN = `2`
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
| 18 | 1 | `02` | MKA Version | `2` | Basic 第 1 字节是版本不是 type；2 = 802.1X-2010，3 = 802.1X-2020（XPN 的 KS SSCI 字段随 v3 出现） |
| 19 | 1 | `20` | Key Server Priority | `32` | 数值越小越优先 |
| 20 | 2 | `702c` | KS/Desired/Cap + BodyLen | `0x702c` | KS=0 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | MAC ‖ Port ID |
| 30 | 12 | `bb01bb02bb03bb04bb05bb06` | Actor MI | `bb01bb02bb03bb04bb05bb06` | 12 字节成员标识 |
| 42 | 4 | `00000002` | Actor MN | `2` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `4d41435345432d4c41422d434b4e3031` | CKN | `4d41435345432d4c41422d434b4e3031` | ASCII 'MACSEC-LAB-CKN01'，两端必须一致 |
| 66 | 1 | `03` | Param type | `3` | MACsec SAK Use |
| 67 | 1 | `30` | Latest/Old AN tx rx | `0x30` | Latest AN=0 tx=1 rx=1; Old AN=0 tx=0 rx=0 |
| 68 | 2 | `1028` | Plain/Delay + BodyLen | `1028` | plain_tx=0 plain_rx=0 delay_protect=1 body=40 |
| 70 | 12 | `aa01aa02aa03aa04aa05aa06` | Latest KS MI | `aa01aa02aa03aa04aa05aa06` | KI 的 MI 部分 |
| 82 | 4 | `00000001` | Latest KN | `1` | KI 的 Key Number |
| 86 | 4 | `00000001` | Latest lowest PN | `1` | 抗重放窗口下沿 |
| 90 | 12 | `000000000000000000000000` | Old KS MI | `000000000000000000000000` | 无旧钥时为 0 |
| 102 | 4 | `00000000` | Old KN | `0` |  |
| 106 | 4 | `00000001` | Old lowest PN | `1` |  |
| 110 | 1 | `01` | Param type | `1` | Live Peer List |
| 111 | 1 | `00` | KS SSCI LSB | `0x00` | XPN：发送方 SC 的 SSCI 低位（默认分配：SCI 最大者 0x0001）；非 XPN 时为 0 |
| 112 | 2 | `0010` | Body length | `16` |  |
| 114 | 12 | `aa01aa02aa03aa04aa05aa06` | Peer 1 MI | `aa01aa02aa03aa04aa05aa06` | 对端成员标识 |
| 126 | 4 | `00000002` | Peer 1 MN | `2` | 对端已确认的报文号 |
| 130 | 16 | `fa7298e7878b252961061fb6a9e41c24` | MKA ICV | `fa7298e7878b252961061fb6a9e41c24` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0b 88 8e 03 05  ................
0010  00 80 02 20 70 2c 02 00  00 00 00 0b 00 01 bb 01  ... p,..........
0020  bb 02 bb 03 bb 04 bb 05  bb 06 00 00 00 02 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 03 30 10 28 aa 01  aa 02 aa 03 aa 04 aa 05  01.0.(..........
0050  aa 06 00 00 00 01 00 00  00 01 00 00 00 00 00 00  ................
0060  00 00 00 00 00 00 00 00  00 00 00 00 00 01 01 00  ................
0070  00 10 aa 01 aa 02 aa 03  aa 04 aa 05 aa 06 00 00  ................
0080  00 02 fa 72 98 e7 87 8b  25 29 61 06 1f b6 a9 e4  ...r....%)a.....
0090  1c 24                                             .$
```

## 帧 5 — A MN=3: both sides using SAK (tx+rx), session up

**EAPOL-MKA  MN=3  Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `01:80:c2:00:00:03`（146 B）
- 作用：A MN=3: both sides using SAK (tx+rx), session up
- Key Server 标志 = `True`，优先级 = `16`，MN = `3`
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
| 18 | 1 | `02` | MKA Version | `2` | Basic 第 1 字节是版本不是 type；2 = 802.1X-2010，3 = 802.1X-2020（XPN 的 KS SSCI 字段随 v3 出现） |
| 19 | 1 | `10` | Key Server Priority | `16` | 数值越小越优先 |
| 20 | 2 | `f02c` | KS/Desired/Cap + BodyLen | `0xf02c` | KS=1 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | MAC ‖ Port ID |
| 30 | 12 | `aa01aa02aa03aa04aa05aa06` | Actor MI | `aa01aa02aa03aa04aa05aa06` | 12 字节成员标识 |
| 42 | 4 | `00000003` | Actor MN | `3` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `4d41435345432d4c41422d434b4e3031` | CKN | `4d41435345432d4c41422d434b4e3031` | ASCII 'MACSEC-LAB-CKN01'，两端必须一致 |
| 66 | 1 | `03` | Param type | `3` | MACsec SAK Use |
| 67 | 1 | `30` | Latest/Old AN tx rx | `0x30` | Latest AN=0 tx=1 rx=1; Old AN=0 tx=0 rx=0 |
| 68 | 2 | `1028` | Plain/Delay + BodyLen | `1028` | plain_tx=0 plain_rx=0 delay_protect=1 body=40 |
| 70 | 12 | `aa01aa02aa03aa04aa05aa06` | Latest KS MI | `aa01aa02aa03aa04aa05aa06` | KI 的 MI 部分 |
| 82 | 4 | `00000001` | Latest KN | `1` | KI 的 Key Number |
| 86 | 4 | `00000001` | Latest lowest PN | `1` | 抗重放窗口下沿 |
| 90 | 12 | `000000000000000000000000` | Old KS MI | `000000000000000000000000` | 无旧钥时为 0 |
| 102 | 4 | `00000000` | Old KN | `0` |  |
| 106 | 4 | `00000001` | Old lowest PN | `1` |  |
| 110 | 1 | `01` | Param type | `1` | Live Peer List |
| 111 | 1 | `00` | KS SSCI LSB | `0x00` | XPN：发送方 SC 的 SSCI 低位（默认分配：SCI 最大者 0x0001）；非 XPN 时为 0 |
| 112 | 2 | `0010` | Body length | `16` |  |
| 114 | 12 | `bb01bb02bb03bb04bb05bb06` | Peer 1 MI | `bb01bb02bb03bb04bb05bb06` | 对端成员标识 |
| 126 | 4 | `00000002` | Peer 1 MN | `2` | 对端已确认的报文号 |
| 130 | 16 | `cc552dbffb7cc4529909d88c4a7815bc` | MKA ICV | `cc552dbffb7cc4529909d88c4a7815bc` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0a 88 8e 03 05  ................
0010  00 80 02 10 f0 2c 02 00  00 00 00 0a 00 01 aa 01  .....,..........
0020  aa 02 aa 03 aa 04 aa 05  aa 06 00 00 00 03 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 03 30 10 28 aa 01  aa 02 aa 03 aa 04 aa 05  01.0.(..........
0050  aa 06 00 00 00 01 00 00  00 01 00 00 00 00 00 00  ................
0060  00 00 00 00 00 00 00 00  00 00 00 00 00 01 01 00  ................
0070  00 10 bb 01 bb 02 bb 03  bb 04 bb 05 bb 06 00 00  ................
0080  00 02 cc 55 2d bf fb 7c  c4 52 99 09 d8 8c 4a 78  ...U-..|.R....Jx
0090  15 bc                                             ..
```

## 帧 6 — B MN=3 keepalive

**EAPOL-MKA  MN=3  非 Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `01:80:c2:00:00:03`（146 B）
- 作用：B MN=3 keepalive
- Key Server 标志 = `False`，优先级 = `32`，MN = `3`
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
| 18 | 1 | `02` | MKA Version | `2` | Basic 第 1 字节是版本不是 type；2 = 802.1X-2010，3 = 802.1X-2020（XPN 的 KS SSCI 字段随 v3 出现） |
| 19 | 1 | `20` | Key Server Priority | `32` | 数值越小越优先 |
| 20 | 2 | `702c` | KS/Desired/Cap + BodyLen | `0x702c` | KS=0 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | MAC ‖ Port ID |
| 30 | 12 | `bb01bb02bb03bb04bb05bb06` | Actor MI | `bb01bb02bb03bb04bb05bb06` | 12 字节成员标识 |
| 42 | 4 | `00000003` | Actor MN | `3` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `4d41435345432d4c41422d434b4e3031` | CKN | `4d41435345432d4c41422d434b4e3031` | ASCII 'MACSEC-LAB-CKN01'，两端必须一致 |
| 66 | 1 | `03` | Param type | `3` | MACsec SAK Use |
| 67 | 1 | `30` | Latest/Old AN tx rx | `0x30` | Latest AN=0 tx=1 rx=1; Old AN=0 tx=0 rx=0 |
| 68 | 2 | `1028` | Plain/Delay + BodyLen | `1028` | plain_tx=0 plain_rx=0 delay_protect=1 body=40 |
| 70 | 12 | `aa01aa02aa03aa04aa05aa06` | Latest KS MI | `aa01aa02aa03aa04aa05aa06` | KI 的 MI 部分 |
| 82 | 4 | `00000001` | Latest KN | `1` | KI 的 Key Number |
| 86 | 4 | `00000001` | Latest lowest PN | `1` | 抗重放窗口下沿 |
| 90 | 12 | `000000000000000000000000` | Old KS MI | `000000000000000000000000` | 无旧钥时为 0 |
| 102 | 4 | `00000000` | Old KN | `0` |  |
| 106 | 4 | `00000001` | Old lowest PN | `1` |  |
| 110 | 1 | `01` | Param type | `1` | Live Peer List |
| 111 | 1 | `00` | KS SSCI LSB | `0x00` | XPN：发送方 SC 的 SSCI 低位（默认分配：SCI 最大者 0x0001）；非 XPN 时为 0 |
| 112 | 2 | `0010` | Body length | `16` |  |
| 114 | 12 | `aa01aa02aa03aa04aa05aa06` | Peer 1 MI | `aa01aa02aa03aa04aa05aa06` | 对端成员标识 |
| 126 | 4 | `00000003` | Peer 1 MN | `3` | 对端已确认的报文号 |
| 130 | 16 | `74084a6c7b5e29ca826469b2c5b1cf04` | MKA ICV | `74084a6c7b5e29ca826469b2c5b1cf04` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0b 88 8e 03 05  ................
0010  00 80 02 20 70 2c 02 00  00 00 00 0b 00 01 bb 01  ... p,..........
0020  bb 02 bb 03 bb 04 bb 05  bb 06 00 00 00 03 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 03 30 10 28 aa 01  aa 02 aa 03 aa 04 aa 05  01.0.(..........
0050  aa 06 00 00 00 01 00 00  00 01 00 00 00 00 00 00  ................
0060  00 00 00 00 00 00 00 00  00 00 00 00 00 01 01 00  ................
0070  00 10 aa 01 aa 02 aa 03  aa 04 aa 05 aa 06 00 00  ................
0080  00 03 74 08 4a 6c 7b 5e  29 ca 82 64 69 b2 c5 b1  ..t.Jl{^)..di...
0090  cf 04                                             ..
```

## 帧 7 — A→B ICMP echo seq=1 (encrypted)

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

## 帧 8 — B→A ICMP seq=1 (encrypted)

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

## 帧 9 — A→B ICMP echo seq=2 (encrypted)

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

## 帧 10 — B→A ICMP seq=2 (encrypted)

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

## 帧 11 — A→B ICMP echo seq=3 (encrypted)

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

## 帧 12 — B→A ICMP seq=3 (encrypted)

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

## 帧 13 — A→B ES=1 no-SCI PN=9 (encrypted)

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
