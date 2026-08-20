# 逐帧解析 — `macsec-ieee-gcm-aes-128-integrity.pcap`

共 **1** 帧。每条消息包含：作用说明、偏移字段表、十六进制；MACsec 另附解密后的内层 IPv4/ICMP。

## 总览

| # | 长度 | SA → DA | 一句话 |
|---:|---:|---|---|
| 1 | 86 | `7a:0d:46:df:99:8d` → `d6:09:b1:f0:56:63` | IEEE GCM-AES-128 integrity-only test vector |

## 帧 1 — IEEE GCM-AES-128 integrity-only test vector

**MACsec  PN=2999092325  integrity-only  SC=1  ICV=OK**

- 方向：`7a:0d:46:df:99:8d` → `d6:09:b1:f0:56:63`（86 B）
- 作用：IEEE GCM-AES-128 integrity-only test vector
- TCI `0x22`：integrity-only；PN = `2999092325`；SCI = `12153524c0895e81`
- GCM IV = SCI‖PN = `12153524c0895e81b2c28465`
- AAD = DA‖SA‖SecTAG‖User Data（P 为空）
- ICV 校验 = `True`

### 线上字段（相对帧起始偏移）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 6 | `d609b1f05663` | DA | `d6:09:b1:f0:56:63` | 对端单播 MAC |
| 6 | 6 | `7a0d46df998d` | SA | `7a:0d:46:df:99:8d` | 发送方 MAC |
| 12 | 2 | `88e5` | EtherType | `0x88e5` | 802.1AE MACsec |
| 14 | 1 | `22` | TCI/AN | `0x22` | V=0 ES=0 SC=1 SCB=0 E=0 C=0 AN=2；模式 integrity-only |
| 15 | 1 | `2a` | SL | `42` | Secure Data < 48 时填长度，否则 0 |
| 16 | 4 | `b2c28465` | PN (wire) | `2999092325 (0xb2c28465)` | 抗重放；GCM IV 的低 32 bit |
| 20 | 8 | `12153524c0895e81` | SCI | `12153524c0895e81` | 显式携带；IV 高 64 bit |
| 28 | 42 | `08000f101112131415161718191a1b1c…33340001` | Secure Data | `08000f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233340001` | 明文 User Data（仅完整性） |
| 70 | 16 | `f09478a9b09007d06f46e9b6a1da25dd` | MACsec ICV | `f09478a9b09007d06f46e9b6a1da25dd` | GCM tag；校验 通过 |

### 解密后 User Data（相对 User Data 起始）

| Offset | Len | Hex | Field | Value | 说明 |
|---:|---:|---|---|---|---|
| 0 | 2 | `0800` | 原 EtherType | `0x0800` | 被保护的内层类型，不是 0x88E5 |
| 2 | 40 | `0f101112131415161718191a1b1c1d1e…33340001` | User Data | `0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233340001` | 非标准 IPv4 头（如 IEEE 测试向量） |

```
0000  08 00 0f 10 11 12 13 14  15 16 17 18 19 1a 1b 1c  ................
0010  1d 1e 1f 20 21 22 23 24  25 26 27 28 29 2a 2b 2c  ... !"#$%&'()*+,
0020  2d 2e 2f 30 31 32 33 34  00 01                    -./01234..
```

### 整帧十六进制

```
0000  d6 09 b1 f0 56 63 7a 0d  46 df 99 8d 88 e5 22 2a  ....Vcz.F....."*
0010  b2 c2 84 65 12 15 35 24  c0 89 5e 81 08 00 0f 10  ...e..5$..^.....
0020  11 12 13 14 15 16 17 18  19 1a 1b 1c 1d 1e 1f 20  ............... 
0030  21 22 23 24 25 26 27 28  29 2a 2b 2c 2d 2e 2f 30  !"#$%&'()*+,-./0
0040  31 32 33 34 00 01 f0 94  78 a9 b0 90 07 d0 6f 46  1234....x.....oF
0050  e9 b6 a1 da 25 dd                                 ....%.
```
