# MACsec Lab

[Status]()
[Platform]()
[License](#license)

**IEEE 802.1AE (MACsec)** + **IEEE 802.1X MKA** 实验室。对照 [IPsec_Lab](../IPsec_Lab) / [IEEE_802.1X_Lab](../IEEE_802.1X_Lab) 的做法：给出 **可在 Wireshark 打开的参考抓包**、**按字段解析的报文**，以及用 Python 实现的 GCM-AES / AES-CMAC / AES-KeyWrap（ICV 可验证、SAK 可解开）。

本机 WSL2 内核 **未开启** `CONFIG_MACSEC`，因此数据面抓包不是 `ip macsec` 内核卸载出来的，而是按 802.1AE 组出来、密码学与 [IEEE GCM 测试向量](https://ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf) 对齐的帧。MKA 走真实 EAPOL（EtherType `0x888E`，Packet Type **5**），Wireshark 的 `mka` 解析器可以直接展开。

> **仅供学习。** 仓库里的 CAK/SAK 是演示密钥，一克隆就当已经泄露。不要用在任何真实网络上。



## 目录

- [能看到什么](#能看到什么)
- [快速开始](#快速开始)
- [抓包对照](#抓包对照)
- [协议与密钥](#协议与密钥)
- [目录结构](#目录结构)
- [Wireshark](#wireshark)
- [Live 实验（可选）](#live-实验可选)
- [免责声明](#免责声明)



## 能看到什么


| 平面  | 协议               | 抓包里有什么                                                                                              |
| --- | ---------------- | --------------------------------------------------------------------------------------------------- |
| 控制面 | **MKA**（KaY）     | Key Server 选举、CKN、Live/Potential Peer List、KEK 封装的 **Distributed SAK**、**SAK Use**、AES-CMAC **ICV** |
| 数据面 | **MACsec**（SecY） | EtherType `0x88E5`、SecTAG（TCI/AN/SL/PN/SCI）、Secure Data、GCM **ICV**                                 |
| 对照  | IEEE 官方向量        | 公开的 GCM-AES-128 完整性 / 机密性测试帧，本仓库测试会逐字节比对 ICV                                                        |


PSK CAK（`session-full.pcap`）：两端事先配好同一把 CAK/CKN，MKA 直接开始。

```mermaid
sequenceDiagram
    autonumber
    participant A as node-a (KS prio 16)
    participant B as node-b (prio 32)
    Note over A,B: same CAK / CKN (PSK)
    A->>B: EAPOL-MKA MN=1 Key Server hello
    B->>A: EAPOL-MKA MN=1 Potential Peer List
    A->>B: Live Peer + Distributed SAK + SAK Use (tx)
    B->>A: Live Peer + SAK Use (tx+rx)
    A->>B: SAK Use (tx+rx) session up
    B->>A: keepalive
    A->>B: MACsec ICMP (E=1 C=1 PN=1..)
    B->>A: MACsec ICMP
```

EAP 鉴权成功之后（`mka-after-eap.pcap`）：MKPDU 参数集与上面相同，但 CAK/CKN 来自 EAP **MSK**，Authenticator 当 Key Server。EAP-TLS 本身在 [IEEE_802.1X_Lab](https://github.com/johnfu-ai/IEEE_802.1X_Lab)；本抓包从 **EAP-Success** 起。

```mermaid
sequenceDiagram
    autonumber
    participant Auth as Authenticator (KS prio 0)
    participant Supp as Supplicant (prio 255)
    Note over Auth,Supp: EAP-TLS done (IEEE_802.1X_Lab); MSK on both sides
    Auth->>Supp: EAP-Success
    Note over Auth,Supp: CAK = KDF(MSK[0:16], IEEE8021 EAP CAK, mac1||mac2)
    Auth->>Supp: EAPOL-MKA MN=1 Key Server hello
    Supp->>Auth: EAPOL-MKA MN=1 Potential Peer List
    Auth->>Supp: Live Peer + Distributed SAK + SAK Use (tx)
    Supp->>Auth: Live Peer + SAK Use (tx+rx)
    Auth->>Supp: SAK Use (tx+rx) session up
    Supp->>Auth: keepalive
```





## 快速开始

```bash
cd ~/MACsec_Lab
python3 -m pip install -r requirements.txt   # cryptography

make test        # IEEE 向量 + 往返加解密 / ICV / SAK unwrap
make generate    # 写出 captures/*.pcap 和 captures/decoded/*.md
make verify      # 测试 + tshark 能否认出 mka / macsec
```

然后打开 `captures/session-full.pcap`，过滤 `mka || macsec`。

字段级解析（本仓库自己的解析器，不依赖 Wireshark 密钥表）：

- `[docs/protocol-analysis.md](docs/protocol-analysis.md)` — 完整会话里 **每一条消息** 的偏移表 + 内层 ICMP
- `[captures/decoded/01-mka-handshake.md](captures/decoded/01-mka-handshake.md)`
- `[captures/decoded/02-macsec-encrypted.md](captures/decoded/02-macsec-encrypted.md)`
- `[captures/decoded/03-macsec-integrity-only.md](captures/decoded/03-macsec-integrity-only.md)`
- `[captures/decoded/11-mka-after-eap.md](captures/decoded/11-mka-after-eap.md)` — EAP-Success 之后的 MKA（Authenticator / Supplicant）
- `[captures/decoded/13-mka-rekey.md](captures/decoded/13-mka-rekey.md)` — SAK 重加密全过程（AN=0 → AN=1 → 旧钥退役）



## 抓包对照


| 文件                                        | 用途                                         |
| ----------------------------------------- | ------------------------------------------ |
| `captures/mka-handshake.pcap`             | 6 帧 MKA（PSK CAK）：hello → 选 KS → 分发 SAK → 双方 SAK Use |
| `captures/mka-after-eap.pcap`             | EAP-Success 之后：Authenticator 为 KS，CAK 从 MSK 派生     |
| `captures/mka-rekey.pcap`                 | SAK 重加密：AN=0 → AN=1，双 SA 并存 → 旧钥退役（[docs/lifecycle.md](docs/lifecycle.md)） |
| `captures/macsec-lab-encrypted.pcap`      | 实验室 GCM-AES-128，载荷加密                       |
| `captures/macsec-lab-integrity-only.pcap` | 同一 ICMP，`E=0 C=0`，内层 IPv4 明文可见             |
| `captures/macsec-ieee-gcm-aes-128-*.pcap` | IEEE 公布的 GCM 测试向量（128-bit key）               |
| `captures/macsec-ieee-gcm-aes-256-*.pcap` | 同一帧换 256-bit key 的 IEEE 向量（Randall §2.1.2/§2.2.2） |
| `captures/session-full.pcap`              | PSK MKA + 加密数据面，一条故事线                      |
| `captures/keys.json`                      | 演示 PSK CAK 与 EAP 派生 CAK / CKN / SAK（含重加密 SAK#2）/ KEK / ICK |




## 协议与密钥

CAK **从不**直接加密用户帧。PSK 预共享的是 CAK+CKN，不是 SAK。KEK/ICK 从 CAK 派生；SAK 由 Key Server **另生成**，用 AES-KeyWrap(KEK) 放进 MKPDU：

```
PSK 配置 或  EAP MSK
 ├── CAK   根密钥（只派生 KEK/ICK）
 └── CKN   名字（不是密钥；KDF 的 context）

CAK + CKN
 ├── KEK = KDF(..., "IEEE8021 KEK")  → AES-KW 封装 SAK
 └── ICK = KDF(..., "IEEE8021 ICK")  → MKPDU ICV

Key Server 随机生成 SAK  →  AES-KW(KEK, SAK) 经 MKA 分发  →  SecY GCM
```

层次图、五个对象对照表、KDF 公式：[docs/key-hierarchy.md](docs/key-hierarchy.md)。

- **EAPOL-MKA Packet Type = 5**（IEEE 802.1X Table 11-3 `0000 0101`）。Type 6 是 EAPOL-Announcement，不是 MKA。
- EAP 成功之后：`CAK = KDF(MSK[0:16], "IEEE8021 EAP CAK", mac1||mac2)`，CKN 同理用 `"IEEE8021 EAP CKN"`（label 16 字节，与 KEK/ICK 的 12 字节不同）。见 `mka-after-eap.pcap`。
- MACsec ICV：GCM 的 16 字节 tag。IV = SCI(8) ‖ PN(4)。AAD 含 DA‖SA‖SecTAG（含 `0x88E5`）；完整性模式还要把 User Data 放进 AAD。
- MKA ICV：`AES-CMAC(ICK, DA‖SA‖0x888E‖EAPOL−ICV)`（802.1X 9.4.1）。

详解：

- [docs/key-hierarchy.md](docs/key-hierarchy.md) — CAK / CKN / KEK / ICK / SAK 是什么、怎么生成
- [docs/lifecycle.md](docs/lifecycle.md) — 换钥（rekey）、AN/KN、PN 耗尽、重放窗口、Delay Protect、判死
- [docs/cipher-suites.md](docs/cipher-suites.md) — GCM-AES-128/256/XPN 四套件对照、协商、XPN nonce 构造
- [docs/protocol-analysis.md](docs/protocol-analysis.md) — **每一条消息的偏移级解析**（session-full）
- [docs/mka-protocol-analysis.md](docs/mka-protocol-analysis.md) — 含 PSK vs EAP 成功之后
- [docs/macsec-protocol-analysis.md](docs/macsec-protocol-analysis.md)
- [docs/glossary.md](docs/glossary.md)
- [docs/deployments.md](docs/deployments.md) — 真实世界：Linux wpa_supplicant/ip macsec、厂商、NIC 卸载、运维清单
- [docs/vs-ipsec.md](docs/vs-ipsec.md)（对照 IPsec_Lab）
- [docs/attacks.md](docs/attacks.md)
- [docs/standards-map.md](docs/standards-map.md)



## 目录结构

```
MACsec_Lab/
├── README.md
├── Makefile
├── macsec_lab/          # 组包 / 解包 / 派生密钥
├── tests/               # IEEE 向量必须通过
├── captures/            # 参考 pcap + keys.json + decoded/
├── docs/                # 协议说明、拓扑、抓包指南
├── examples/c/          # SecTAG 比特布局（教学子集）
└── scripts/             # generate / verify / live netns
```



## Wireshark

```
mka || macsec
eapol.type == 5
eap.code == 3
eth.type == 0x88e5
macsec.sl || macsec.an
```

让 Wireshark 自己验 MKA ICV、解开 SAK：Preferences → Protocols → **MKA** → CKN 表，填 `keys.json` 里的 CKN 与 CAK。

Windows 下打开 WSL 文件：

```
\\wsl$\<发行版>\home\<用户>\MACsec_Lab\captures\session-full.pcap
```



## Live 实验（可选）

不需要内核 MACsec 模块。两个 netns + veth + 网桥，用 AF_PACKET 把参考帧打到线上，tcpdump 抓一份 `captures/live-session.pcap`：

```bash
sudo make lab
sudo make down
```

Linux 网桥默认丢掉 PAE 组播 `01:80:c2:00:00:03`。脚本会把 `group_fwd_mask` 写成 `8`（与 802.1X Lab 相同）。若抓不到 MKA，见 [docs/troubleshooting.md](docs/troubleshooting.md)。

若内核打开了 `CONFIG_MACSEC`，可以用 `ip macsec` 做真实 SecY；本仓库的解析器同样能读那种 pcap（需要你提供 SAK）。

## 免责声明

本项目只用于理解 IEEE 802.1AE / 802.1X MKA 的帧格式与密钥关系。

- 不要把这里的密钥、镜像或脚本部署到生产或你没有明确授权的网络。
- `keys.json` 与代码里的 CAK/SAK 是 **演示材料**。
- 作者不对误用承担责任。



## License

MIT。IEEE 标准文本本身不在本仓库；实现按公开条款（802.1X 9.x / 11.x 图、802.1AE Clause 9/14、Randall GCM 测试向量）编写。