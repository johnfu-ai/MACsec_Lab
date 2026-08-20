# 逐帧解析 — `mka-after-eap.pcap`

共 **7** 帧。每条消息包含：作用说明、偏移字段表、十六进制；MACsec 另附解密后的内层 IPv4/ICMP。

## 总览

| # | 长度 | SA → DA | 一句话 |
|---:|---:|---|---|
| 1 | 60 | `02:00:00:00:00:0a` → `02:00:00:00:00:0b` | EAP-Success (Authenticator → Supplicant; MSK already on both sides) |
| 2 | 82 | `02:00:00:00:00:0a` → `01:80:c2:00:00:03` | Authenticator MN=1 hello (claim Key Server, no peers yet) |
| 3 | 102 | `02:00:00:00:00:0b` → `01:80:c2:00:00:03` | Supplicant MN=1 hello (saw Authenticator; Potential Peer List; not Key Server) |
| 4 | 178 | `02:00:00:00:00:0a` → `01:80:c2:00:00:03` | Authenticator MN=2 Key Server: Live Peer List + Distributed SAK + SAK Use (tx) |
| 5 | 146 | `02:00:00:00:00:0b` → `01:80:c2:00:00:03` | Supplicant MN=2: Live Peer List + SAK Use (tx+rx) after installing SAK |
| 6 | 146 | `02:00:00:00:00:0a` → `01:80:c2:00:00:03` | Authenticator MN=3: both sides using SAK (tx+rx), session up |
| 7 | 146 | `02:00:00:00:00:0b` → `01:80:c2:00:00:03` | Supplicant MN=3 keepalive |

## 帧 1 — EAP-Success (Authenticator → Supplicant; MSK already on both sides)

**EAPOL-EAP  Success**

- 方向：`02:00:00:00:00:0a` → `02:00:00:00:00:0b`（60 B）
- 作用：EAP-Success (Authenticator → Supplicant; MSK already on both sides)
- EAPOL Type = `0`（0 = EAP-Packet），EAP Code = `3`

### 逐字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `02000000000b` | DA | `02:00:00:00:00:0b` | 对端单播 MAC |
| 6 | 6 | `02000000000a` | SA | `02:00:00:00:00:0a` | 发送方 MAC |
| 12 | 2 | `888e` | EtherType | `0x888e` | 802.1X EAPOL |
| 14 | 1 | `03` | EAPOL Version | `3` | 3 = 802.1X-2010 |
| 15 | 1 | `00` | EAPOL Type | `0` | 0 = EAP-Packet（MKA 是 5） |
| 16 | 2 | `0004` | Packet Body Length | `4` | EAP 报文长度 |
| 18 | 1 | `03` | EAP Code | `3` | Success |
| 19 | 1 | `02` | EAP Identifier | `2` | 与前序 Request 对应 |
| 20 | 2 | `0004` | EAP Length | `4` | Success/Failure 固定为 4 |
| 22 | 38 | `00000000000000000000000000000000…00000000` | Ethernet padding | `00…` | 38 字节 |

### 十六进制

```
0000  02 00 00 00 00 0b 02 00  00 00 00 0a 88 8e 03 00  ................
0010  00 04 03 02 00 04 00 00  00 00 00 00 00 00 00 00  ................
0020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
0030  00 00 00 00 00 00 00 00  00 00 00 00              ............
```

## 帧 2 — Authenticator MN=1 hello (claim Key Server, no peers yet)

**EAPOL-MKA  MN=1  Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `01:80:c2:00:00:03`（82 B）
- 作用：Authenticator MN=1 hello (claim Key Server, no peers yet)
- Key Server 标志 = `True`，优先级 = `0`，MN = `1`
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
| 18 | 1 | `02` | MKA Version | `2` | Basic 第 1 字节是版本不是 type |
| 19 | 1 | `00` | Key Server Priority | `0` | 数值越小越优先 |
| 20 | 2 | `f02c` | KS/Desired/Cap + BodyLen | `0xf02c` | KS=1 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | MAC ‖ Port ID |
| 30 | 12 | `cc01cc02cc03cc04cc05cc06` | Actor MI | `cc01cc02cc03cc04cc05cc06` | 12 字节成员标识 |
| 42 | 4 | `00000001` | Actor MN | `1` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `3a4c35b14d5ffb90dd69687cf15fac47` | CKN | `3a4c35b14d5ffb90dd69687cf15fac47` | EAP-derived CKN (KDF); both sides must match |
| 66 | 16 | `b29d5e984c57c1d7fc5f518a698fca19` | MKA ICV | `b29d5e984c57c1d7fc5f518a698fca19` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0a 88 8e 03 05  ................
0010  00 40 02 00 f0 2c 02 00  00 00 00 0a 00 01 cc 01  .@...,..........
0020  cc 02 cc 03 cc 04 cc 05  cc 06 00 00 00 01 00 80  ................
0030  c2 01 3a 4c 35 b1 4d 5f  fb 90 dd 69 68 7c f1 5f  ..:L5.M_...ih|._
0040  ac 47 b2 9d 5e 98 4c 57  c1 d7 fc 5f 51 8a 69 8f  .G..^.LW..._Q.i.
0050  ca 19                                             ..
```

## 帧 3 — Supplicant MN=1 hello (saw Authenticator; Potential Peer List; not Key Server)

**EAPOL-MKA  MN=1  非 Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `01:80:c2:00:00:03`（102 B）
- 作用：Supplicant MN=1 hello (saw Authenticator; Potential Peer List; not Key Server)
- Key Server 标志 = `False`，优先级 = `255`，MN = `1`
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
| 18 | 1 | `02` | MKA Version | `2` | Basic 第 1 字节是版本不是 type |
| 19 | 1 | `ff` | Key Server Priority | `255` | 数值越小越优先 |
| 20 | 2 | `702c` | KS/Desired/Cap + BodyLen | `0x702c` | KS=0 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | MAC ‖ Port ID |
| 30 | 12 | `dd01dd02dd03dd04dd05dd06` | Actor MI | `dd01dd02dd03dd04dd05dd06` | 12 字节成员标识 |
| 42 | 4 | `00000001` | Actor MN | `1` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `3a4c35b14d5ffb90dd69687cf15fac47` | CKN | `3a4c35b14d5ffb90dd69687cf15fac47` | EAP-derived CKN (KDF); both sides must match |
| 66 | 1 | `02` | Param type | `2` | Potential Peer List |
| 67 | 1 | `00` | KS SSCI LSB | `0` | 非 XPN 时为 0 |
| 68 | 2 | `0010` | Body length | `16` |  |
| 70 | 12 | `cc01cc02cc03cc04cc05cc06` | Peer 1 MI | `cc01cc02cc03cc04cc05cc06` | 对端成员标识 |
| 82 | 4 | `00000001` | Peer 1 MN | `1` | 对端已确认的报文号 |
| 86 | 16 | `242e281871803b675852fa1e6c8cbf06` | MKA ICV | `242e281871803b675852fa1e6c8cbf06` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0b 88 8e 03 05  ................
0010  00 54 02 ff 70 2c 02 00  00 00 00 0b 00 01 dd 01  .T..p,..........
0020  dd 02 dd 03 dd 04 dd 05  dd 06 00 00 00 01 00 80  ................
0030  c2 01 3a 4c 35 b1 4d 5f  fb 90 dd 69 68 7c f1 5f  ..:L5.M_...ih|._
0040  ac 47 02 00 00 10 cc 01  cc 02 cc 03 cc 04 cc 05  .G..............
0050  cc 06 00 00 00 01 24 2e  28 18 71 80 3b 67 58 52  ......$.(.q.;gXR
0060  fa 1e 6c 8c bf 06                                 ..l...
```

## 帧 4 — Authenticator MN=2 Key Server: Live Peer List + Distributed SAK + SAK Use (tx)

**EAPOL-MKA  MN=2  Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `01:80:c2:00:00:03`（178 B）
- 作用：Authenticator MN=2 Key Server: Live Peer List + Distributed SAK + SAK Use (tx)
- Key Server 标志 = `True`，优先级 = `0`，MN = `2`
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
| 19 | 1 | `00` | Key Server Priority | `0` | 数值越小越优先 |
| 20 | 2 | `f02c` | KS/Desired/Cap + BodyLen | `0xf02c` | KS=1 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | MAC ‖ Port ID |
| 30 | 12 | `cc01cc02cc03cc04cc05cc06` | Actor MI | `cc01cc02cc03cc04cc05cc06` | 12 字节成员标识 |
| 42 | 4 | `00000002` | Actor MN | `2` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `3a4c35b14d5ffb90dd69687cf15fac47` | CKN | `3a4c35b14d5ffb90dd69687cf15fac47` | EAP-derived CKN (KDF); both sides must match |
| 66 | 1 | `04` | Param type | `4` | Distributed SAK |
| 67 | 1 | `00` | AN + Conf. offset | `0x00` | AN=0 offset_code=0 (→前 0 字节不加密) |
| 68 | 2 | `001c` | Body length | `28` | 28 = 默认 GCM-AES-128 |
| 70 | 4 | `00000001` | Key Number | `1` | 本把 SAK 的编号 |
| 74 | 24 | `ea420ced1f518e6eb7c2c4ecd6d29360b4122cde79692275` | AES-KW(SAK) | `ea420ced1f518e6eb7c2c4ecd6d29360b4122cde79692275` | AES-KeyWrap(KEK, SAK)，24 B = 16 B SAK + 8 B wrap IV；解开 = b1b2b3b4b5b6b7b8b9babbbcbdbebfc0 |
| 98 | 1 | `03` | Param type | `3` | MACsec SAK Use |
| 99 | 1 | `20` | Latest/Old AN tx rx | `0x20` | Latest AN=0 tx=1 rx=0; Old AN=0 tx=0 rx=0 |
| 100 | 2 | `1028` | Plain/Delay + BodyLen | `1028` | plain_tx=0 plain_rx=0 delay_protect=1 body=40 |
| 102 | 12 | `cc01cc02cc03cc04cc05cc06` | Latest KS MI | `cc01cc02cc03cc04cc05cc06` | KI 的 MI 部分 |
| 114 | 4 | `00000001` | Latest KN | `1` | KI 的 Key Number |
| 118 | 4 | `00000001` | Latest lowest PN | `1` | 抗重放窗口下沿 |
| 122 | 12 | `000000000000000000000000` | Old KS MI | `000000000000000000000000` | 无旧钥时为 0 |
| 134 | 4 | `00000000` | Old KN | `0` |  |
| 138 | 4 | `00000001` | Old lowest PN | `1` |  |
| 142 | 1 | `01` | Param type | `1` | Live Peer List |
| 143 | 1 | `00` | KS SSCI LSB | `0` | 非 XPN 时为 0 |
| 144 | 2 | `0010` | Body length | `16` |  |
| 146 | 12 | `dd01dd02dd03dd04dd05dd06` | Peer 1 MI | `dd01dd02dd03dd04dd05dd06` | 对端成员标识 |
| 158 | 4 | `00000001` | Peer 1 MN | `1` | 对端已确认的报文号 |
| 162 | 16 | `c34b31959eae711de056d73fa16df219` | MKA ICV | `c34b31959eae711de056d73fa16df219` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0a 88 8e 03 05  ................
0010  00 a0 02 00 f0 2c 02 00  00 00 00 0a 00 01 cc 01  .....,..........
0020  cc 02 cc 03 cc 04 cc 05  cc 06 00 00 00 02 00 80  ................
0030  c2 01 3a 4c 35 b1 4d 5f  fb 90 dd 69 68 7c f1 5f  ..:L5.M_...ih|._
0040  ac 47 04 00 00 1c 00 00  00 01 ea 42 0c ed 1f 51  .G.........B...Q
0050  8e 6e b7 c2 c4 ec d6 d2  93 60 b4 12 2c de 79 69  .n.......`..,.yi
0060  22 75 03 20 10 28 cc 01  cc 02 cc 03 cc 04 cc 05  "u. .(..........
0070  cc 06 00 00 00 01 00 00  00 01 00 00 00 00 00 00  ................
0080  00 00 00 00 00 00 00 00  00 00 00 00 00 01 01 00  ................
0090  00 10 dd 01 dd 02 dd 03  dd 04 dd 05 dd 06 00 00  ................
00a0  00 01 c3 4b 31 95 9e ae  71 1d e0 56 d7 3f a1 6d  ...K1...q..V.?.m
00b0  f2 19                                             ..
```

## 帧 5 — Supplicant MN=2: Live Peer List + SAK Use (tx+rx) after installing SAK

**EAPOL-MKA  MN=2  非 Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `01:80:c2:00:00:03`（146 B）
- 作用：Supplicant MN=2: Live Peer List + SAK Use (tx+rx) after installing SAK
- Key Server 标志 = `False`，优先级 = `255`，MN = `2`
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
| 19 | 1 | `ff` | Key Server Priority | `255` | 数值越小越优先 |
| 20 | 2 | `702c` | KS/Desired/Cap + BodyLen | `0x702c` | KS=0 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | MAC ‖ Port ID |
| 30 | 12 | `dd01dd02dd03dd04dd05dd06` | Actor MI | `dd01dd02dd03dd04dd05dd06` | 12 字节成员标识 |
| 42 | 4 | `00000002` | Actor MN | `2` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `3a4c35b14d5ffb90dd69687cf15fac47` | CKN | `3a4c35b14d5ffb90dd69687cf15fac47` | EAP-derived CKN (KDF); both sides must match |
| 66 | 1 | `03` | Param type | `3` | MACsec SAK Use |
| 67 | 1 | `30` | Latest/Old AN tx rx | `0x30` | Latest AN=0 tx=1 rx=1; Old AN=0 tx=0 rx=0 |
| 68 | 2 | `1028` | Plain/Delay + BodyLen | `1028` | plain_tx=0 plain_rx=0 delay_protect=1 body=40 |
| 70 | 12 | `cc01cc02cc03cc04cc05cc06` | Latest KS MI | `cc01cc02cc03cc04cc05cc06` | KI 的 MI 部分 |
| 82 | 4 | `00000001` | Latest KN | `1` | KI 的 Key Number |
| 86 | 4 | `00000001` | Latest lowest PN | `1` | 抗重放窗口下沿 |
| 90 | 12 | `000000000000000000000000` | Old KS MI | `000000000000000000000000` | 无旧钥时为 0 |
| 102 | 4 | `00000000` | Old KN | `0` |  |
| 106 | 4 | `00000001` | Old lowest PN | `1` |  |
| 110 | 1 | `01` | Param type | `1` | Live Peer List |
| 111 | 1 | `00` | KS SSCI LSB | `0` | 非 XPN 时为 0 |
| 112 | 2 | `0010` | Body length | `16` |  |
| 114 | 12 | `cc01cc02cc03cc04cc05cc06` | Peer 1 MI | `cc01cc02cc03cc04cc05cc06` | 对端成员标识 |
| 126 | 4 | `00000002` | Peer 1 MN | `2` | 对端已确认的报文号 |
| 130 | 16 | `4f0eba018e0b03cb8f2fd08126d84a79` | MKA ICV | `4f0eba018e0b03cb8f2fd08126d84a79` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0b 88 8e 03 05  ................
0010  00 80 02 ff 70 2c 02 00  00 00 00 0b 00 01 dd 01  ....p,..........
0020  dd 02 dd 03 dd 04 dd 05  dd 06 00 00 00 02 00 80  ................
0030  c2 01 3a 4c 35 b1 4d 5f  fb 90 dd 69 68 7c f1 5f  ..:L5.M_...ih|._
0040  ac 47 03 30 10 28 cc 01  cc 02 cc 03 cc 04 cc 05  .G.0.(..........
0050  cc 06 00 00 00 01 00 00  00 01 00 00 00 00 00 00  ................
0060  00 00 00 00 00 00 00 00  00 00 00 00 00 01 01 00  ................
0070  00 10 cc 01 cc 02 cc 03  cc 04 cc 05 cc 06 00 00  ................
0080  00 02 4f 0e ba 01 8e 0b  03 cb 8f 2f d0 81 26 d8  ..O......../..&.
0090  4a 79                                             Jy
```

## 帧 6 — Authenticator MN=3: both sides using SAK (tx+rx), session up

**EAPOL-MKA  MN=3  Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0a` → `01:80:c2:00:00:03`（146 B）
- 作用：Authenticator MN=3: both sides using SAK (tx+rx), session up
- Key Server 标志 = `True`，优先级 = `0`，MN = `3`
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
| 19 | 1 | `00` | Key Server Priority | `0` | 数值越小越优先 |
| 20 | 2 | `f02c` | KS/Desired/Cap + BodyLen | `0xf02c` | KS=1 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000a0001` | SCI | `02000000000a0001` | MAC ‖ Port ID |
| 30 | 12 | `cc01cc02cc03cc04cc05cc06` | Actor MI | `cc01cc02cc03cc04cc05cc06` | 12 字节成员标识 |
| 42 | 4 | `00000003` | Actor MN | `3` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `3a4c35b14d5ffb90dd69687cf15fac47` | CKN | `3a4c35b14d5ffb90dd69687cf15fac47` | EAP-derived CKN (KDF); both sides must match |
| 66 | 1 | `03` | Param type | `3` | MACsec SAK Use |
| 67 | 1 | `30` | Latest/Old AN tx rx | `0x30` | Latest AN=0 tx=1 rx=1; Old AN=0 tx=0 rx=0 |
| 68 | 2 | `1028` | Plain/Delay + BodyLen | `1028` | plain_tx=0 plain_rx=0 delay_protect=1 body=40 |
| 70 | 12 | `cc01cc02cc03cc04cc05cc06` | Latest KS MI | `cc01cc02cc03cc04cc05cc06` | KI 的 MI 部分 |
| 82 | 4 | `00000001` | Latest KN | `1` | KI 的 Key Number |
| 86 | 4 | `00000001` | Latest lowest PN | `1` | 抗重放窗口下沿 |
| 90 | 12 | `000000000000000000000000` | Old KS MI | `000000000000000000000000` | 无旧钥时为 0 |
| 102 | 4 | `00000000` | Old KN | `0` |  |
| 106 | 4 | `00000001` | Old lowest PN | `1` |  |
| 110 | 1 | `01` | Param type | `1` | Live Peer List |
| 111 | 1 | `00` | KS SSCI LSB | `0` | 非 XPN 时为 0 |
| 112 | 2 | `0010` | Body length | `16` |  |
| 114 | 12 | `dd01dd02dd03dd04dd05dd06` | Peer 1 MI | `dd01dd02dd03dd04dd05dd06` | 对端成员标识 |
| 126 | 4 | `00000002` | Peer 1 MN | `2` | 对端已确认的报文号 |
| 130 | 16 | `7a9571b286e2427f4083f44357de2b03` | MKA ICV | `7a9571b286e2427f4083f44357de2b03` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0a 88 8e 03 05  ................
0010  00 80 02 00 f0 2c 02 00  00 00 00 0a 00 01 cc 01  .....,..........
0020  cc 02 cc 03 cc 04 cc 05  cc 06 00 00 00 03 00 80  ................
0030  c2 01 3a 4c 35 b1 4d 5f  fb 90 dd 69 68 7c f1 5f  ..:L5.M_...ih|._
0040  ac 47 03 30 10 28 cc 01  cc 02 cc 03 cc 04 cc 05  .G.0.(..........
0050  cc 06 00 00 00 01 00 00  00 01 00 00 00 00 00 00  ................
0060  00 00 00 00 00 00 00 00  00 00 00 00 00 01 01 00  ................
0070  00 10 dd 01 dd 02 dd 03  dd 04 dd 05 dd 06 00 00  ................
0080  00 02 7a 95 71 b2 86 e2  42 7f 40 83 f4 43 57 de  ..z.q...B.@..CW.
0090  2b 03                                             +.
```

## 帧 7 — Supplicant MN=3 keepalive

**EAPOL-MKA  MN=3  非 Key Server  ICV=OK**

- 方向：`02:00:00:00:00:0b` → `01:80:c2:00:00:03`（146 B）
- 作用：Supplicant MN=3 keepalive
- Key Server 标志 = `False`，优先级 = `255`，MN = `3`
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
| 19 | 1 | `ff` | Key Server Priority | `255` | 数值越小越优先 |
| 20 | 2 | `702c` | KS/Desired/Cap + BodyLen | `0x702c` | KS=0 Desired=1 Cap=3(完整性+机密性，offset 0/30/50) body_len=44 |
| 22 | 8 | `02000000000b0001` | SCI | `02000000000b0001` | MAC ‖ Port ID |
| 30 | 12 | `dd01dd02dd03dd04dd05dd06` | Actor MI | `dd01dd02dd03dd04dd05dd06` | 12 字节成员标识 |
| 42 | 4 | `00000003` | Actor MN | `3` | 本参与者报文序号 |
| 46 | 4 | `0080c201` | Algorithm Agility | `0080c201` | 00-80-C2-01 = 802.1X-2010 AES-CMAC |
| 50 | 16 | `3a4c35b14d5ffb90dd69687cf15fac47` | CKN | `3a4c35b14d5ffb90dd69687cf15fac47` | EAP-derived CKN (KDF); both sides must match |
| 66 | 1 | `03` | Param type | `3` | MACsec SAK Use |
| 67 | 1 | `30` | Latest/Old AN tx rx | `0x30` | Latest AN=0 tx=1 rx=1; Old AN=0 tx=0 rx=0 |
| 68 | 2 | `1028` | Plain/Delay + BodyLen | `1028` | plain_tx=0 plain_rx=0 delay_protect=1 body=40 |
| 70 | 12 | `cc01cc02cc03cc04cc05cc06` | Latest KS MI | `cc01cc02cc03cc04cc05cc06` | KI 的 MI 部分 |
| 82 | 4 | `00000001` | Latest KN | `1` | KI 的 Key Number |
| 86 | 4 | `00000001` | Latest lowest PN | `1` | 抗重放窗口下沿 |
| 90 | 12 | `000000000000000000000000` | Old KS MI | `000000000000000000000000` | 无旧钥时为 0 |
| 102 | 4 | `00000000` | Old KN | `0` |  |
| 106 | 4 | `00000001` | Old lowest PN | `1` |  |
| 110 | 1 | `01` | Param type | `1` | Live Peer List |
| 111 | 1 | `00` | KS SSCI LSB | `0` | 非 XPN 时为 0 |
| 112 | 2 | `0010` | Body length | `16` |  |
| 114 | 12 | `cc01cc02cc03cc04cc05cc06` | Peer 1 MI | `cc01cc02cc03cc04cc05cc06` | 对端成员标识 |
| 126 | 4 | `00000003` | Peer 1 MN | `3` | 对端已确认的报文号 |
| 130 | 16 | `26d2a9ea0c334c44acc65676c1fbfc97` | MKA ICV | `26d2a9ea0c334c44acc65676c1fbfc97` | AES-CMAC(ICK)；校验 通过 |

### 十六进制

```
0000  01 80 c2 00 00 03 02 00  00 00 00 0b 88 8e 03 05  ................
0010  00 80 02 ff 70 2c 02 00  00 00 00 0b 00 01 dd 01  ....p,..........
0020  dd 02 dd 03 dd 04 dd 05  dd 06 00 00 00 03 00 80  ................
0030  c2 01 3a 4c 35 b1 4d 5f  fb 90 dd 69 68 7c f1 5f  ..:L5.M_...ih|._
0040  ac 47 03 30 10 28 cc 01  cc 02 cc 03 cc 04 cc 05  .G.0.(..........
0050  cc 06 00 00 00 01 00 00  00 01 00 00 00 00 00 00  ................
0060  00 00 00 00 00 00 00 00  00 00 00 00 00 01 01 00  ................
0070  00 10 cc 01 cc 02 cc 03  cc 04 cc 05 cc 06 00 00  ................
0080  00 03 26 d2 a9 ea 0c 33  4c 44 ac c6 56 76 c1 fb  ..&....3LD..Vv..
0090  fc 97                                             ..
```
