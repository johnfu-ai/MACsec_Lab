# 逐帧解析 — `macsec-ieee-gcm-aes-256-encrypt.pcap`

共 **1** 帧。每条消息包含：作用说明、偏移字段表、十六进制；MACsec 另附解密后的内层 IPv4/ICMP。

## 总览

| # | 长度 | SA → DA | 一句话 |
|---:|---:|---|---|
| 1 | 92 | `7a:0d:46:df:99:8d` → `d6:09:b1:f0:56:63` | IEEE GCM-AES-256 confidentiality test vector (Randall 2.2.2) |

## 帧 1 — IEEE GCM-AES-256 confidentiality test vector (Randall 2.2.2)

**MACsec  PN=2999092325  confidentiality+integrity  SC=1  ICV=OK**

- 方向：`7a:0d:46:df:99:8d` → `d6:09:b1:f0:56:63`（92 B）
- 作用：IEEE GCM-AES-256 confidentiality test vector (Randall 2.2.2)
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
| 28 | 48 | `e2006eb42f5277022d9b19925bc419d7…56ab7836` | Secure Data | `e2006eb42f5277022d9b19925bc419d7a592666c925fe2ef718eb4e308efeaa7c5273b394118860a5be2a97f56ab7836` | 密文 |
| 76 | 16 | `5ca597cdbb3edb8d1a1151ea0af7b436` | MACsec ICV | `5ca597cdbb3edb8d1a1151ea0af7b436` | GCM tag；校验 通过 |

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
0010  b2 c2 84 65 12 15 35 24  c0 89 5e 81 e2 00 6e b4  ...e..5$..^...n.
0020  2f 52 77 02 2d 9b 19 92  5b c4 19 d7 a5 92 66 6c  /Rw.-...[.....fl
0030  92 5f e2 ef 71 8e b4 e3  08 ef ea a7 c5 27 3b 39  ._..q........';9
0040  41 18 86 0a 5b e2 a9 7f  56 ab 78 36 5c a5 97 cd  A...[...V.x6\...
0050  bb 3e db 8d 1a 11 51 ea  0a f7 b4 36              .>....Q....6
```
