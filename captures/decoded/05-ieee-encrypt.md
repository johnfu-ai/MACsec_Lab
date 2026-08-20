# 逐帧解析 — `macsec-ieee-gcm-aes-128-encrypt.pcap`

共 **1** 帧。每条消息包含：作用说明、偏移字段表、十六进制；MACsec 另附解密后的内层 IPv4/ICMP。

## 总览

| # | 长度 | SA → DA | 一句话 |
|---:|---:|---|---|
| 1 | 92 | `7a:0d:46:df:99:8d` → `d6:09:b1:f0:56:63` | IEEE GCM-AES-128 confidentiality test vector |

## 帧 1 — IEEE GCM-AES-128 confidentiality test vector

**MACsec  PN=2999092325  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`7a:0d:46:df:99:8d` → `d6:09:b1:f0:56:63`（92 B）
- 作用：IEEE GCM-AES-128 confidentiality test vector
- TCI `0x2e`：confidentiality+integrity；PN = `2999092325`；SCI = `12153524c0895e81`
- GCM IV = SCI‖PN = `12153524c0895e81b2c28465`
- AAD = DA‖SA‖SecTAG（P = User Data）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `d609b1f05663` | DA | `d6:09:b1:f0:56:63` | 对端单播 MAC |
| 6 | 6 | `7a0d46df998d` | SA | `7a:0d:46:df:99:8d` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `2e` | TCI/AN | `0x2e` | V=0 ES=0 SC=1 SCB=0 E=1 C=1 AN=2；模式 confidentiality+integrity |
| 15 | 1 | `00` | SL | `0` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `b2c28465` | PN (wire) | `2999092325 (0xb2c28465)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `12153524c0895e81` | SCI | `12153524c0895e81` | 显式携带；IV 高 64 bit |
| 28 | 48 | `701afa1cc039c0d765128a665dab6924…7fba713d` | Secure Data | `701afa1cc039c0d765128a665dab69243899bf7318ccdc81c9931da17fbe8edd7d17cb8b4c26fc81e3284f2b7fba713d` | 密文 |
| 76 | 16 | `4f8d55e7d3f06fd5a13c0c29b9d5b880` | MACsec ICV | `4f8d55e7d3f06fd5a13c0c29b9d5b880` | GCM tag；校验 通过 |

### 解密后 User Data（相对 User Data 起始）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 2 | `0800` | 原 EtherType | `0x0800` | 被保护的内层类型，不是 0x88E5 |
| 2 | 46 | `0f101112131415161718191a1b1c1d1e…393a0002` | User Data | `0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a0002` | 非标准 IPv4 头（如 IEEE 测试向量） |

```
0000  08 00 0f 10 11 12 13 14  15 16 17 18 19 1a 1b 1c  ................
0010  1d 1e 1f 20 21 22 23 24  25 26 27 28 29 2a 2b 2c  ... !"#$%&'()*+,
0020  2d 2e 2f 30 31 32 33 34  35 36 37 38 39 3a 00 02  -./0123456789:..
```

### 整帧十六进制

```
0000  d6 09 b1 f0 56 63 7a 0d  46 df 99 8d 88 e5 2e 00  ....Vcz.F.......
0010  b2 c2 84 65 12 15 35 24  c0 89 5e 81 70 1a fa 1c  ...e..5$..^.p...
0020  c0 39 c0 d7 65 12 8a 66  5d ab 69 24 38 99 bf 73  .9..e..f].i$8..s
0030  18 cc dc 81 c9 93 1d a1  7f be 8e dd 7d 17 cb 8b  ............}...
0040  4c 26 fc 81 e3 28 4f 2b  7f ba 71 3d 4f 8d 55 e7  L&...(O+..q=O.U.
0050  d3 f0 6f d5 a1 3c 0c 29  b9 d5 b8 80              ..o..<.)....
```
