# 逐帧解析 — `mka-multi-peer.pcap`

共 **11** 帧。每条消息包含：作用说明、偏移字段表、十六进制；MACsec 另附解密后的内层 IPv4/ICMP。

## 总览

| # | 长度 | SA → DA | 一句话 |
|---:|---:|---|---|
| 1 | 82 | `02:00:00:00:00:0a` → `01:80:c2:00:00:03` | A MN=1 hello (Key Server claim, prio 16 — smallest priority wins) |
| 2 | 102 | `02:00:00:00:00:0b` → `01:80:c2:00:00:03` | B MN=1 hello (Potential Peer List: A; prio 32) |
| 3 | 118 | `02:00:00:00:00:0c` → `01:80:c2:00:00:03` | C MN=1 hello (Potential Peer List: A + B; prio 48 — three members, one CAK/CKN) |
| 4 | 194 | `02:00:00:00:00:0a` → `01:80:c2:00:00:03` | A MN=2 Key Server: ONE Distributed SAK for the whole CA + SAK Use (tx) + Live Peer List with TWO tuples |
| 5 | 162 | `02:00:00:00:00:0b` → `01:80:c2:00:00:03` | B MN=2: SAK Use tx+rx (installed the SAK); Live Peer List [A, C] |
| 6 | 162 | `02:00:00:00:00:0c` → `01:80:c2:00:00:03` | C MN=2: SAK Use tx+rx; Live Peer List [A, B] |
| 7 | 162 | `02:00:00:00:00:0a` → `01:80:c2:00:00:03` | A MN=3: SAK Use tx+rx — all three members live on the single SAK |
| 8 | 84 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | A→B data PN=1 AN=0 SC=1 ICMP seq=20 — node-a's own SC/SCI; explicit SCI because the CA has more than two members |
| 9 | 84 | `02:00:00:00:00:0b` → `02:00:00:00:00:0c` | B→C data PN=1 AN=0 SC=1 ICMP seq=21 — node-b's own SC/SCI; explicit SCI because the CA has more than two members |
| 10 | 84 | `02:00:00:00:00:0c` → `02:00:00:00:00:0a` | C→A data PN=1 AN=0 SC=1 ICMP seq=22 — node-c's own SC/SCI; explicit SCI because the CA has more than two members |
| 11 | 162 | `02:00:00:00:00:0c` → `01:80:c2:00:00:03` | C MN=3 keepalive: one CAK, one KS, one SAK, three unidirectional SCs |

## 帧 1 — A MN=1 hello (Key Server claim, prio 16 — smallest priority wins)

**EAPOL-MKA  MN=1  Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `01:80:c2:00:00:03`（82 B）
- 作用：A MN=1 hello (Key Server claim, prio 16 — smallest priority wins)
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

## 帧 2 — B MN=1 hello (Potential Peer List: A; prio 32)

**EAPOL-MKA  MN=1  非 Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `01:80:c2:00:00:03`（102 B）
- 作用：B MN=1 hello (Potential Peer List: A; prio 32)
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

## 帧 3 — C MN=1 hello (Potential Peer List: A + B; prio 48 — three members, one CAK/CKN)

**EAPOL-MKA  MN=1  非 Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0c` → `01:80:c2:00:00:03`（118 B）
- 作用：C MN=1 hello (Potential Peer List: A + B; prio 48 — three members, one CAK/CKN)
- Key Server 标志 = `False`，优先级 = `48`，MN = `1`
- ICV 校验 = `True`（AES-CMAC(ICK, DA‖SA‖0x888E‖EAPOL−ICV)）

### 逐字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `0180c2000003` | DA | `01:80:c2:00:00:03` | PAE 组播（MKA 必须用组地址） |
| 6 | 6 | `02000000000c` | SA | `02:00:00:00:00:0c` | 发送方 MAC |
| 12 | 2 | `888e` | EtherType | `0x888e` | 802.1X EAPOL |
| 14 | 1 | `03` | EAPOL Version | `3` | 3 = 802.1X-2010 |
| 15 | 1 | `05` | EAPOL Type | `5` | 5 = EAPOL-MKA（不是 6） |
| 16 | 2 | `0064` | Packet Body Length | `100` | 含 ICV，不含以太网头 |
| 18 | 1 | `02` | MKA Version | `2` | Basic 第 1 字节是版本不是 type；2 = 802.1X-2010，3 = 802.1X-2020（XPN 的 KS SSCI 字段随 v3 出现） |
| 19 | 1 | `30` | Key Server Priority | `48` | 数值越小越优先 |
| 20 | 2 | `702c` | KS/Desired/Cap + BodyLen | `0x702c` | KS=0 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000c0001` | SCI | `02000000000c0001` | MAC ‖ Port ID |
| 30 | 12 | `cc11cc12cc13cc14cc15cc16` | Actor MI | `cc11cc12cc13cc14cc15cc16` | 12 字节成员标识 |
| 42 | 4 | `00000001` | Actor MN | `1` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `4d41435345432d4c41422d434b4e3031` | CKN | `4d41435345432d4c41422d434b4e3031` | ASCII 'MACSEC-LAB-CKN01'，两端必须一致 |
| 66 | 1 | `02` | Param type | `2` | Potential Peer List |
| 67 | 1 | `00` | KS SSCI LSB | `0x00` | XPN：发送方 SC 的 SSCI 低位（默认分配：SCI 最大者 0x0001）；非 XPN 时为 0 |
| 68 | 2 | `0020` | Body length | `32` |  |
| 70 | 12 | `aa01aa02aa03aa04aa05aa06` | Peer 1 MI | `aa01aa02aa03aa04aa05aa06` | 对端成员标识 |
| 82 | 4 | `00000001` | Peer 1 MN | `1` | 对端已确认的报文号 |
| 86 | 12 | `bb01bb02bb03bb04bb05bb06` | Peer 2 MI | `bb01bb02bb03bb04bb05bb06` | 对端成员标识 |
| 98 | 4 | `00000001` | Peer 2 MN | `1` | 对端已确认的报文号 |
| 102 | 16 | `c188605c3e38ee940dc4a009ef4fa5d0` | MKA ICV | `c188605c3e38ee940dc4a009ef4fa5d0` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0c 88 8e 03 05  ................
0010  00 64 02 30 70 2c 02 00  00 00 00 0c 00 01 cc 11  .d.0p,..........
0020  cc 12 cc 13 cc 14 cc 15  cc 16 00 00 00 01 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 02 00 00 20 aa 01  aa 02 aa 03 aa 04 aa 05  01... ..........
0050  aa 06 00 00 00 01 bb 01  bb 02 bb 03 bb 04 bb 05  ................
0060  bb 06 00 00 00 01 c1 88  60 5c 3e 38 ee 94 0d c4  ........`\>8....
0070  a0 09 ef 4f a5 d0                                 ...O..
```

## 帧 4 — A MN=2 Key Server: ONE Distributed SAK for the whole CA + SAK Use (tx) + Live Peer List with TWO tuples

**EAPOL-MKA  MN=2  Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `01:80:c2:00:00:03`（194 B）
- 作用：A MN=2 Key Server: ONE Distributed SAK for the whole CA + SAK Use (tx) + Live Peer List with TWO tuples
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
| 16 | 2 | `00b0` | Packet Body Length | `176` | 含 ICV，不含以太网头 |
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
| 144 | 2 | `0020` | Body length | `32` |  |
| 146 | 12 | `bb01bb02bb03bb04bb05bb06` | Peer 1 MI | `bb01bb02bb03bb04bb05bb06` | 对端成员标识 |
| 158 | 4 | `00000001` | Peer 1 MN | `1` | 对端已确认的报文号 |
| 162 | 12 | `cc11cc12cc13cc14cc15cc16` | Peer 2 MI | `cc11cc12cc13cc14cc15cc16` | 对端成员标识 |
| 174 | 4 | `00000001` | Peer 2 MN | `1` | 对端已确认的报文号 |
| 178 | 16 | `557a74e4f51f03b0cd3b8a213b80b387` | MKA ICV | `557a74e4f51f03b0cd3b8a213b80b387` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0a 88 8e 03 05  ................
0010  00 b0 02 10 f0 2c 02 00  00 00 00 0a 00 01 aa 01  .....,..........
0020  aa 02 aa 03 aa 04 aa 05  aa 06 00 00 00 02 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 04 00 00 1c 00 00  00 01 37 f3 40 ac 59 e7  01........7.@.Y.
0050  db 5f 16 4e 8c 83 0b 35  f6 71 d8 c5 83 c1 95 77  ._.N...5.q.....w
0060  cc d2 03 20 10 28 aa 01  aa 02 aa 03 aa 04 aa 05  ... .(..........
0070  aa 06 00 00 00 01 00 00  00 01 00 00 00 00 00 00  ................
0080  00 00 00 00 00 00 00 00  00 00 00 00 00 01 01 00  ................
0090  00 20 bb 01 bb 02 bb 03  bb 04 bb 05 bb 06 00 00  . ..............
00a0  00 01 cc 11 cc 12 cc 13  cc 14 cc 15 cc 16 00 00  ................
00b0  00 01 55 7a 74 e4 f5 1f  03 b0 cd 3b 8a 21 3b 80  ..Uzt......;.!;.
00c0  b3 87                                             ..
```

## 帧 5 — B MN=2: SAK Use tx+rx (installed the SAK); Live Peer List [A, C]

**EAPOL-MKA  MN=2  非 Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `01:80:c2:00:00:03`（162 B）
- 作用：B MN=2: SAK Use tx+rx (installed the SAK); Live Peer List [A, C]
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
| 16 | 2 | `0090` | Packet Body Length | `144` | 含 ICV，不含以太网头 |
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
| 112 | 2 | `0020` | Body length | `32` |  |
| 114 | 12 | `aa01aa02aa03aa04aa05aa06` | Peer 1 MI | `aa01aa02aa03aa04aa05aa06` | 对端成员标识 |
| 126 | 4 | `00000002` | Peer 1 MN | `2` | 对端已确认的报文号 |
| 130 | 12 | `cc11cc12cc13cc14cc15cc16` | Peer 2 MI | `cc11cc12cc13cc14cc15cc16` | 对端成员标识 |
| 142 | 4 | `00000001` | Peer 2 MN | `1` | 对端已确认的报文号 |
| 146 | 16 | `3c820273db7d85277165580b48d417de` | MKA ICV | `3c820273db7d85277165580b48d417de` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0b 88 8e 03 05  ................
0010  00 90 02 20 70 2c 02 00  00 00 00 0b 00 01 bb 01  ... p,..........
0020  bb 02 bb 03 bb 04 bb 05  bb 06 00 00 00 02 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 03 30 10 28 aa 01  aa 02 aa 03 aa 04 aa 05  01.0.(..........
0050  aa 06 00 00 00 01 00 00  00 01 00 00 00 00 00 00  ................
0060  00 00 00 00 00 00 00 00  00 00 00 00 00 01 01 00  ................
0070  00 20 aa 01 aa 02 aa 03  aa 04 aa 05 aa 06 00 00  . ..............
0080  00 02 cc 11 cc 12 cc 13  cc 14 cc 15 cc 16 00 00  ................
0090  00 01 3c 82 02 73 db 7d  85 27 71 65 58 0b 48 d4  ..<..s.}.'qeX.H.
00a0  17 de                                             ..
```

## 帧 6 — C MN=2: SAK Use tx+rx; Live Peer List [A, B]

**EAPOL-MKA  MN=2  非 Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0c` → `01:80:c2:00:00:03`（162 B）
- 作用：C MN=2: SAK Use tx+rx; Live Peer List [A, B]
- Key Server 标志 = `False`，优先级 = `48`，MN = `2`
- ICV 校验 = `True`（AES-CMAC(ICK, DA‖SA‖0x888E‖EAPOL−ICV)）

### 逐字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `0180c2000003` | DA | `01:80:c2:00:00:03` | PAE 组播（MKA 必须用组地址） |
| 6 | 6 | `02000000000c` | SA | `02:00:00:00:00:0c` | 发送方 MAC |
| 12 | 2 | `888e` | EtherType | `0x888e` | 802.1X EAPOL |
| 14 | 1 | `03` | EAPOL Version | `3` | 3 = 802.1X-2010 |
| 15 | 1 | `05` | EAPOL Type | `5` | 5 = EAPOL-MKA（不是 6） |
| 16 | 2 | `0090` | Packet Body Length | `144` | 含 ICV，不含以太网头 |
| 18 | 1 | `02` | MKA Version | `2` | Basic 第 1 字节是版本不是 type；2 = 802.1X-2010，3 = 802.1X-2020（XPN 的 KS SSCI 字段随 v3 出现） |
| 19 | 1 | `30` | Key Server Priority | `48` | 数值越小越优先 |
| 20 | 2 | `702c` | KS/Desired/Cap + BodyLen | `0x702c` | KS=0 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000c0001` | SCI | `02000000000c0001` | MAC ‖ Port ID |
| 30 | 12 | `cc11cc12cc13cc14cc15cc16` | Actor MI | `cc11cc12cc13cc14cc15cc16` | 12 字节成员标识 |
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
| 112 | 2 | `0020` | Body length | `32` |  |
| 114 | 12 | `aa01aa02aa03aa04aa05aa06` | Peer 1 MI | `aa01aa02aa03aa04aa05aa06` | 对端成员标识 |
| 126 | 4 | `00000002` | Peer 1 MN | `2` | 对端已确认的报文号 |
| 130 | 12 | `bb01bb02bb03bb04bb05bb06` | Peer 2 MI | `bb01bb02bb03bb04bb05bb06` | 对端成员标识 |
| 142 | 4 | `00000002` | Peer 2 MN | `2` | 对端已确认的报文号 |
| 146 | 16 | `650b8669b72f7b3d8fb91f75b65707d3` | MKA ICV | `650b8669b72f7b3d8fb91f75b65707d3` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0c 88 8e 03 05  ................
0010  00 90 02 30 70 2c 02 00  00 00 00 0c 00 01 cc 11  ...0p,..........
0020  cc 12 cc 13 cc 14 cc 15  cc 16 00 00 00 02 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 03 30 10 28 aa 01  aa 02 aa 03 aa 04 aa 05  01.0.(..........
0050  aa 06 00 00 00 01 00 00  00 01 00 00 00 00 00 00  ................
0060  00 00 00 00 00 00 00 00  00 00 00 00 00 01 01 00  ................
0070  00 20 aa 01 aa 02 aa 03  aa 04 aa 05 aa 06 00 00  . ..............
0080  00 02 bb 01 bb 02 bb 03  bb 04 bb 05 bb 06 00 00  ................
0090  00 02 65 0b 86 69 b7 2f  7b 3d 8f b9 1f 75 b6 57  ..e..i./{=...u.W
00a0  07 d3                                             ..
```

## 帧 7 — A MN=3: SAK Use tx+rx — all three members live on the single SAK

**EAPOL-MKA  MN=3  Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `01:80:c2:00:00:03`（162 B）
- 作用：A MN=3: SAK Use tx+rx — all three members live on the single SAK
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
| 16 | 2 | `0090` | Packet Body Length | `144` | 含 ICV，不含以太网头 |
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
| 112 | 2 | `0020` | Body length | `32` |  |
| 114 | 12 | `bb01bb02bb03bb04bb05bb06` | Peer 1 MI | `bb01bb02bb03bb04bb05bb06` | 对端成员标识 |
| 126 | 4 | `00000002` | Peer 1 MN | `2` | 对端已确认的报文号 |
| 130 | 12 | `cc11cc12cc13cc14cc15cc16` | Peer 2 MI | `cc11cc12cc13cc14cc15cc16` | 对端成员标识 |
| 142 | 4 | `00000002` | Peer 2 MN | `2` | 对端已确认的报文号 |
| 146 | 16 | `26d1c82f271a441c9b7f003cc54115b7` | MKA ICV | `26d1c82f271a441c9b7f003cc54115b7` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0a 88 8e 03 05  ................
0010  00 90 02 10 f0 2c 02 00  00 00 00 0a 00 01 aa 01  .....,..........
0020  aa 02 aa 03 aa 04 aa 05  aa 06 00 00 00 03 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 03 30 10 28 aa 01  aa 02 aa 03 aa 04 aa 05  01.0.(..........
0050  aa 06 00 00 00 01 00 00  00 01 00 00 00 00 00 00  ................
0060  00 00 00 00 00 00 00 00  00 00 00 00 00 01 01 00  ................
0070  00 20 bb 01 bb 02 bb 03  bb 04 bb 05 bb 06 00 00  . ..............
0080  00 02 cc 11 cc 12 cc 13  cc 14 cc 15 cc 16 00 00  ................
0090  00 02 26 d1 c8 2f 27 1a  44 1c 9b 7f 00 3c c5 41  ..&../'.D....<.A
00a0  15 b7                                             ..
```

## 帧 8 — A→B data PN=1 AN=0 SC=1 ICMP seq=20 — node-a's own SC/SCI; explicit SCI because the CA has more than two members

**MACsec  PN=1  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（84 B）
- 作用：A→B data PN=1 AN=0 SC=1 ICMP seq=20 — node-a's own SC/SCI; explicit SCI because the CA has more than two members
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
| 28 | 40 | `459d7b17401a006c7e107e01f5bafef3…1c6ef164` | Secure Data | `459d7b17401a006c7e107e01f5bafef3eb307386a93c1bb6ca0830c527f382a4d71abd541c6ef164` | 密文 |
| 68 | 16 | `93ccecd083729a06d8bf7297b097db47` | MACsec ICV | `93ccecd083729a06d8bf7297b097db47` | GCM tag；校验 通过 |

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
| 24 | 2 | `f0a2` | ICMP Checksum | `f0a2` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `0014` | ICMP Sequence | `20` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 64 0a 0a  ..E..&BB..@.$d..
0010  00 0a 0a 0a 00 14 08 00  f0 a2 42 42 00 14 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0b 02 00  00 00 00 0a 88 e5 2c 28  ..............,(
0010  00 00 00 01 02 00 00 00  00 0a 00 01 45 9d 7b 17  ............E.{.
0020  40 1a 00 6c 7e 10 7e 01  f5 ba fe f3 eb 30 73 86  @..l~.~......0s.
0030  a9 3c 1b b6 ca 08 30 c5  27 f3 82 a4 d7 1a bd 54  .<....0.'......T
0040  1c 6e f1 64 93 cc ec d0  83 72 9a 06 d8 bf 72 97  .n.d.....r....r.
0050  b0 97 db 47                                       ...G
```

## 帧 9 — B→C data PN=1 AN=0 SC=1 ICMP seq=21 — node-b's own SC/SCI; explicit SCI because the CA has more than two members

**MACsec  PN=1  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `02:00:00:00:00:0c`（84 B）
- 作用：B→C data PN=1 AN=0 SC=1 ICMP seq=21 — node-b's own SC/SCI; explicit SCI because the CA has more than two members
- TCI `0x2c`：confidentiality+integrity；PN = `1`；SCI = `02000000000b0001`
- GCM IV = SCI‖PN = `02000000000b000100000001`
- AAD = DA‖SA‖SecTAG（P = User Data）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000c` | DA | `02:00:00:00:00:0c` | 对端单播 MAC |
| 6 | 6 | `02000000000b` | SA | `02:00:00:00:00:0b` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `2c` | TCI/AN | `0x2c` | V=0 ES=0 SC=1 SCB=0 E=1 C=1 AN=0；模式 confidentiality+integrity |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `00000001` | PN (wire) | `1 (0x00000001)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `26da7b83c51fa5cd01e3f3731e08c5d8…5a2f65fa` | Secure Data | `26da7b83c51fa5cd01e3f3731e08c5d88cb690717dfdad420540c1d4ae5b58ec877bfefa5a2f65fa` | 密文 |
| 68 | 16 | `1a0d0b8adf0624076ed7edbacc0aac2b` | MACsec ICV | `1a0d0b8adf0624076ed7edbacc0aac2b` | GCM tag；校验 通过 |

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
| 12 | 2 | `2450` | IP Checksum | `2450` |  |
| 14 | 4 | `0a0a0014` | IP Src | `10.10.0.20` |  |
| 18 | 4 | `0a0a001e` | IP Dst | `10.10.0.30` |  |
| 22 | 1 | `08` | ICMP Type | `8` | Echo Request |
| 23 | 1 | `00` | ICMP Code | `0` |  |
| 24 | 2 | `f0a1` | ICMP Checksum | `f0a1` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `0015` | ICMP Sequence | `21` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 50 0a 0a  ..E..&BB..@.$P..
0010  00 14 0a 0a 00 1e 08 00  f0 a1 42 42 00 15 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0c 02 00  00 00 00 0b 88 e5 2c 28  ..............,(
0010  00 00 00 01 02 00 00 00  00 0b 00 01 26 da 7b 83  ............&.{.
0020  c5 1f a5 cd 01 e3 f3 73  1e 08 c5 d8 8c b6 90 71  .......s.......q
0030  7d fd ad 42 05 40 c1 d4  ae 5b 58 ec 87 7b fe fa  }..B.@...[X..{..
0040  5a 2f 65 fa 1a 0d 0b 8a  df 06 24 07 6e d7 ed ba  Z/e.......$.n...
0050  cc 0a ac 2b                                       ...+
```

## 帧 10 — C→A data PN=1 AN=0 SC=1 ICMP seq=22 — node-c's own SC/SCI; explicit SCI because the CA has more than two members

**MACsec  PN=1  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`02:00:00:00:00:0c` → `02:00:00:00:00:0a`（84 B）
- 作用：C→A data PN=1 AN=0 SC=1 ICMP seq=22 — node-c's own SC/SCI; explicit SCI because the CA has more than two members
- TCI `0x2c`：confidentiality+integrity；PN = `1`；SCI = `02000000000c0001`
- GCM IV = SCI‖PN = `02000000000c000100000001`
- AAD = DA‖SA‖SecTAG（P = User Data）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000a` | DA | `02:00:00:00:00:0a` | 对端单播 MAC |
| 6 | 6 | `02000000000c` | SA | `02:00:00:00:00:0c` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `2c` | TCI/AN | `0x2c` | V=0 ES=0 SC=1 SCB=0 E=1 C=1 AN=0；模式 confidentiality+integrity |
| 15 | 1 | `28` | SL | `40` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `00000001` | PN (wire) | `1 (0x00000001)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `02000000000c0001` | SCI | `02000000000c0001` | 显式携带；IV 高 64 bit |
| 28 | 40 | `9f3c36c472f7de91ea615a2f2be88d8e…78f31f2c` | Secure Data | `9f3c36c472f7de91ea615a2f2be88d8ebe23bc3bd33a267e2e79faee27c051d2948ffcc878f31f2c` | 密文 |
| 68 | 16 | `3c59dfd08a072039281c376d1fc8f04a` | MACsec ICV | `3c59dfd08a072039281c376d1fc8f04a` | GCM tag；校验 通过 |

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
| 12 | 2 | `245a` | IP Checksum | `245a` |  |
| 14 | 4 | `0a0a001e` | IP Src | `10.10.0.30` |  |
| 18 | 4 | `0a0a000a` | IP Dst | `10.10.0.10` |  |
| 22 | 1 | `08` | ICMP Type | `8` | Echo Request |
| 23 | 1 | `00` | ICMP Code | `0` |  |
| 24 | 2 | `f0a0` | ICMP Checksum | `f0a0` |  |
| 26 | 2 | `4242` | ICMP Identifier | `16962` |  |
| 28 | 2 | `0016` | ICMP Sequence | `22` | 回显序号 |
| 30 | 10 | `6d61637365632d6c6162` | ICMP Data | `'macsec-lab'` | 10 B payload |

```
0000  08 00 45 00 00 26 42 42  00 00 40 01 24 5a 0a 0a  ..E..&BB..@.$Z..
0010  00 1e 0a 0a 00 0a 08 00  f0 a0 42 42 00 16 6d 61  ..........BB..ma
0020  63 73 65 63 2d 6c 61 62                           csec-lab
```

### 整帧十六进制

```
0000  02 00 00 00 00 0a 02 00  00 00 00 0c 88 e5 2c 28  ..............,(
0010  00 00 00 01 02 00 00 00  00 0c 00 01 9f 3c 36 c4  .............<6.
0020  72 f7 de 91 ea 61 5a 2f  2b e8 8d 8e be 23 bc 3b  r....aZ/+....#.;
0030  d3 3a 26 7e 2e 79 fa ee  27 c0 51 d2 94 8f fc c8  .:&~.y..'.Q.....
0040  78 f3 1f 2c 3c 59 df d0  8a 07 20 39 28 1c 37 6d  x..,<Y.... 9(.7m
0050  1f c8 f0 4a                                       ...J
```

## 帧 11 — C MN=3 keepalive: one CAK, one KS, one SAK, three unidirectional SCs

**EAPOL-MKA  MN=3  非 Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0c` → `01:80:c2:00:00:03`（162 B）
- 作用：C MN=3 keepalive: one CAK, one KS, one SAK, three unidirectional SCs
- Key Server 标志 = `False`，优先级 = `48`，MN = `3`
- ICV 校验 = `True`（AES-CMAC(ICK, DA‖SA‖0x888E‖EAPOL−ICV)）

### 逐字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `0180c2000003` | DA | `01:80:c2:00:00:03` | PAE 组播（MKA 必须用组地址） |
| 6 | 6 | `02000000000c` | SA | `02:00:00:00:00:0c` | 发送方 MAC |
| 12 | 2 | `888e` | EtherType | `0x888e` | 802.1X EAPOL |
| 14 | 1 | `03` | EAPOL Version | `3` | 3 = 802.1X-2010 |
| 15 | 1 | `05` | EAPOL Type | `5` | 5 = EAPOL-MKA（不是 6） |
| 16 | 2 | `0090` | Packet Body Length | `144` | 含 ICV，不含以太网头 |
| 18 | 1 | `02` | MKA Version | `2` | Basic 第 1 字节是版本不是 type；2 = 802.1X-2010，3 = 802.1X-2020（XPN 的 KS SSCI 字段随 v3 出现） |
| 19 | 1 | `30` | Key Server Priority | `48` | 数值越小越优先 |
| 20 | 2 | `702c` | KS/Desired/Cap + BodyLen | `0x702c` | KS=0 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000c0001` | SCI | `02000000000c0001` | MAC ‖ Port ID |
| 30 | 12 | `cc11cc12cc13cc14cc15cc16` | Actor MI | `cc11cc12cc13cc14cc15cc16` | 12 字节成员标识 |
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
| 112 | 2 | `0020` | Body length | `32` |  |
| 114 | 12 | `aa01aa02aa03aa04aa05aa06` | Peer 1 MI | `aa01aa02aa03aa04aa05aa06` | 对端成员标识 |
| 126 | 4 | `00000003` | Peer 1 MN | `3` | 对端已确认的报文号 |
| 130 | 12 | `bb01bb02bb03bb04bb05bb06` | Peer 2 MI | `bb01bb02bb03bb04bb05bb06` | 对端成员标识 |
| 142 | 4 | `00000002` | Peer 2 MN | `2` | 对端已确认的报文号 |
| 146 | 16 | `c1afe546601512fcf81966ad9f4cbaa8` | MKA ICV | `c1afe546601512fcf81966ad9f4cbaa8` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0c 88 8e 03 05  ................
0010  00 90 02 30 70 2c 02 00  00 00 00 0c 00 01 cc 11  ...0p,..........
0020  cc 12 cc 13 cc 14 cc 15  cc 16 00 00 00 03 00 80  ................
0030  c2 01 4d 41 43 53 45 43  2d 4c 41 42 2d 43 4b 4e  ..MACSEC-LAB-CKN
0040  30 31 03 30 10 28 aa 01  aa 02 aa 03 aa 04 aa 05  01.0.(..........
0050  aa 06 00 00 00 01 00 00  00 01 00 00 00 00 00 00  ................
0060  00 00 00 00 00 00 00 00  00 00 00 00 00 01 01 00  ................
0070  00 20 aa 01 aa 02 aa 03  aa 04 aa 05 aa 06 00 00  . ..............
0080  00 03 bb 01 bb 02 bb 03  bb 04 bb 05 bb 06 00 00  ................
0090  00 02 c1 af e5 46 60 15  12 fc f8 19 66 ad 9f 4c  .....F`.....f..L
00a0  ba a8                                             ..
```
