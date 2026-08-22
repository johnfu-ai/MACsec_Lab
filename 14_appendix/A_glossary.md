# 附录 A：术语表（中英对照）

按主题分组的 MACsec / MKA 术语速查。缩写展开与一句话定义；有专题文档的给链接。按 Ctrl+F 搜英文或中文都行。

## A.1 协议与标准

| 术语 | 中文 / 全称 | 一句话定义 |
|---|---|---|
| **MACsec** | MAC Security（媒体访问控制安全） | IEEE 802.1AE 定义的链路层加密/认证协议，EtherType `0x88E5` |
| **MKA** | MACsec Key Agreement（密钥协商协议） | IEEE 802.1X Clause 9/11 定义的控制面，负责选举 KS、分发 SAK；EAPOL Type 5 |
| **802.1AE** | — | MACsec 数据面标准（SecY、SecTAG、GCM），2006 首版、2018 现行版（[第十三章](../13_standards/README.md)） |
| **802.1X** | — | 基于端口的接入认证 + MKA 所在标准；EAPOL 载体，2020 现行版 |
| **EAPOL** | EAP over LAN | 802.1X 的链路层承载（版本 3），目的地址 PAE 组地址 |
| **EAP** | Extensible Authentication Protocol | 认证框架（RFC 3748）；EAP-TLS 等方法产生 MSK |
| **SecY** | MAC Security Entity | 数据面实体：protect/validate 帧的逻辑功能（[第三章](../03_secy/README.md)） |
| **KaY** | Key Agreement Entity | 控制面实体：跑 MKA 状态机、管理密钥材料 |
| **PAE** | Port Access Entity | 端口接入实体（Supplicant/ Authenticator 的统称） |
| **Supplicant** | 求证者/客户端 | EAP 模式下被认证的一端 |
| **Authenticator** | 认证者 | EAP 模式下发起认证的一端（在 MKA 中通常当 Key Server） |
| **CA** | Connectivity Association（连通性关联） | 共享同一 CAK 的成员集合——**不等于点对点**（`mka-multi-peer.pcap`） |
| **CKN** | CAK Name | CA 的名字（标识符，不是密钥）；KDF 的 context |
| **EDE** | Ethernet Data Encryption device | 802.1AEcg 的透明加密盒（中间插入的加/解密设备） |

## A.2 密钥体系（详见[第二章](../02_key_hierarchy/README.md)）

| 术语 | 中文 / 全称 | 一句话定义 |
|---|---|---|
| **CAK** | Connectivity Association Key | CA 的根密钥；PSK 配置或 EAP MSK 派生；**从不**直接加密用户帧 |
| **PSK CAK** | 预共享 CAK | 两端事先配好同一把 CAK+CKN，MKA 直接开始（`mka-handshake.pcap`） |
| **EAP CAK** | — | `KDF(MSK, "IEEE8021 EAP CAK", mac1‖mac2)`——EAP 成功后派生（`mka-after-eap.pcap`） |
| **MSK** | Master Session Key | EAP 认证输出的 64 字节主会话密钥，CAK/CKN 的种子 |
| **KDF** | Key Derivation Function | 802.1X 6.2.1 的 AES-CMAC 计数器模式 KDF（NIST SP 800-108） |
| **KDK** | Key Derivation Key | KDF 的输入密钥（就是 CAK） |
| **KEK** | Key Encrypting Key | `KDF(CAK, "IEEE8021 KEK", CKN[0:16])`；AES-KeyWrap 封装 SAK 用 |
| **ICK** | ICV Key | `KDF(CAK, "IEEE8021 ICK", CKN[0:16])`；只用于 MKPDU 的 AES-CMAC |
| **SAK** | Secure Association Key | Key Server **随机生成**（不是从 CAK 派生）的 GCM 数据面密钥 |
| **KN** | Key Number | KS 给每把 SAK 的编号（KI 的一部分） |
| **KI** | Key Identifier | KS 的 MI(12) ‖ KN(4)：一把 SAK 的全名（SA 标识） |
| **AES-KW** | AES Key Wrap（RFC 3394） | 用 KEK 包裹 SAK 的封装算法，比明文长 8 字节 |
| **AES-CMAC** | — | RFC 4493；MKPDU ICV 与 KDF 的底座 |
| **GCM-AES** | Galois/Counter Mode | 数据面加密+认证模式，tag 即 ICV（[第七章](../07_cipher_suites/README.md)） |
| **Algorithm Agility** | 算法敏捷标识 | Basic 参数集里的 4 字节 `00-80-C2-01`，标记 KDF/ICV 算法族 |

## A.3 通道与关联（数据面结构）

| 术语 | 中文 / 全称 | 一句话定义 |
|---|---|---|
| **SC** | Secure Channel（安全通道） | **单向**的受保护通道，每个发送方向一个 |
| **SCI** | SC Identifier | MAC(6) ‖ Port ID(2)；SC 的标识、GCM IV 的高 64 位 |
| **SA** | Secure Association | SC 内一把 SAK 对应的收发状态（PN 计数、重放窗口）；换钥即换 SA |
| **AN** | Association Number | 2 bit，0-3 轮转；接收方按 (SCI, AN) 选 RX SA |
| **TX/RX SC** | 发送/接收安全通道 | 每个成员 1 个 TX SC + 每个远端成员各 1 个 RX SC |
| **MSDU** | MAC Service Data Unit | 受保护前的原始帧载荷（内层 EtherType+数据） |
| **Confidentiality offset (co)** | 机密性偏移 | 0/30/50：User Data 前缀只认证不加密（`mka-co30.pcap`） |

## A.4 SecTAG 与帧字段（详见[5.4 节](../05_wire_format/5.4_data_plane_frames.md)）

| 术语 | 中文 / 全称 | 一句话定义 |
|---|---|---|
| **SecTAG** | 安全标签 | `0x88E5` 后的 TCI/AN+SL+PN(+SCI) 头 |
| **TCI** | Tag Control Information | SecTAG 第一字节：V/ES/SC/SCB/E/C + AN |
| **V bit** | Version | 协议版本，恒 0 |
| **ES bit** | End Station | 1 = 两成员点对点 CA，可省略 SCI（IV 里仍隐含 `SA‖00-01`） |
| **SC bit** | SCI present | 1 = 显式携带 8 字节 SCI；多成员 CA 必须 |
| **SCB bit** | Single Copy Broadcast | 1 = 单拷贝广播帧（用于组播节能场景） |
| **E bit** | Encryption | 1 = 机密性开启；E=1 时 C 必为 1 |
| **C bit** | Changed/Encrypted | E=0,C=0 仅完整性；E=0,C=1 历史遗留的"仅完整性(改)"组合 |
| **SL** | Short Length | Secure Data < 48 字节时填实际长度，否则 0 |
| **PN** | Packet Number | 32 位包序号：GCM nonce 低半 + 抗重放；XPN 下是 64 位的低 32 位 |
| **Secure Data** | 受保护数据 | 密文（E=1）或明文（E=0）的 User Data + co 明文前缀 |
| **ICV** | Integrity Check Value | MACsec：GCM tag 16 字节；MKA：AES-CMAC 16 字节——两套不同的 ICV |

## A.5 机制与流程

| 术语 | 中文 / 全称 | 一句话定义 |
|---|---|---|
| **Key Server** | 密钥服务器 | CA 内当选的唯一 SAK 生成/分发者（优先级数值最小，平局比 SCI） |
| **KS Priority** | KS 优先级 | Basic 参数集第 2 字节，越小越优先 |
| **MKPDU** | MKA Protocol Data Unit | EAPOL Type 5 里的 MKA 报文（Basic + 参数集 + ICV） |
| **Basic Parameter Set** | 基本参数集 | MKPDU 必备首参数集：版本/优先级/SCI/MI/MN/Agility/CKN |
| **PeerList (Live/Potential)** | 对等体列表 | 类型 1/2：已互认/单向可见的成员（MI+MN 条目） |
| **Distributed SAK** | 分发的 SAK | 类型 4 参数集：KN + 可选套件 ID + AES-KW(KEK, SAK) |
| **Distributed CAK** | 分发的 CAK | 类型 5：PSK 模式的 CAK 在线轮换 |
| **SAK Use** | SAK 使用宣告 | 类型 3：latest/old SA 的 AN+tx+rx、delay protect、LLPN/OLPN |
| **MI / MN** | Member Id / Message Number | 成员标识（12 B 随机）/ 报文序号（MKPDU 反重放） |
| **Rekey (SAK rollover)** | 换钥 | PN 耗尽或策略到期前分发新 SAK，双 SA 并存→排空→退役（`mka-rekey.pcap`） |
| **Replay window** | 重放窗口 | RX SA 的 PN 判定：按序/窗口内乱序接受，低于下沿/重复丢弃（`macsec-replay.pcap`） |
| **Delay Protect** | 延迟保护 | SAK Use 宣告 LLPN 下沿，把重放延迟限死在 hello 周期（`mka-delay-protect.pcap`） |
| **LLPN / OLPN** | Latest/Old lowest PN | 最新/旧 SA 的"仍可接受最低 PN"（delay protect 的地板） |
| **PN exhaustion** | PN 耗尽 | 32 位 PN 用尽前必须换钥：100G 小帧约 29 秒（[6.1 节](../06_lifecycle/6.1_why_rekey.md)） |
| **validate frames** | 帧校验策略 | strict/checked/disabled：ICV 挂与 untagged 帧的处理（[3.4 节](../03_secy/3.4_validate_frames.md)） |
| **fail-open / fail-close** | 失败明文/失败断链 | MKA 死后转发明文（危险）或停止转发（标准期望） |
| **Controlled port** | 受控口 | 只在 MKA 会话建立后放行用户流量的逻辑口 |
| **Uncontrolled port** | 非受控口 | 永远放行 EAPOL/MKA 的逻辑口（鸡生蛋问题的答案） |
| **Group fwd mask** | 组转发掩码 | Linux 网桥放行 PAE 组播的关键开关（`group_fwd_mask=8`） |

## A.6 XPN 专用（详见[7.3 节](../07_cipher_suites/7.3_xpn.md)）

| 术语 | 中文 / 全称 | 一句话定义 |
|---|---|---|
| **XPN** | Extended Packet Number | 64 位 PN 的套件族（802.1AEbw-2013） |
| **SSCI** | Short SCI | 32 位短通道标识，同 SAK 下每 SC 唯一；默认 SCI 最大者 0x0001 |
| **Salt** | 盐值 | 96 位公开 nonce 扰码；默认从 KS SCI 推导 |
| **PN64** | 64 位包序号 | 线上只带低 32 位，高 32 位由接收端 SA 状态恢复 |
| **Cipher Suite ID** | 套件标识 | 8 字节套件编号；默认套件 GCM-AES-128 可省略该字段 |

## A.7 生态与运维

| 术语 | 中文 / 全称 | 一句话定义 |
|---|---|---|
| **MAC Privacy Protection** | MAC 隐私保护 | 802.1AEdk(2023)：填充/整形对抗流量分析 |
| **DevID** | Secure Device Identity（802.1AR） | 设备身份证书，常用于 EAP-TLS → MSK → CAK 链路 |
| **TrustSec / MACsec 市场别名** | — | Cisco 早期商用 LinkSec 的市场化名称 |
| **YANG/MIB** | 管理模型 | RFC 9191 等：只管管理面不碰协议 |
| **`ip macsec`** | — | Linux 手工 SecY 管理 CLI（`CONFIG_MACSEC`） |
| **wpa_supplicant** | — | Linux 上跑 MKA 的用户态实现（KaY） |
| **NIC offload** | 网卡卸载 | SecY 在网卡执行：线速 GCM、捕获点语义变化（[第十一章](../11_deployments/README.md)） |
| **`InPktsBadTag` 等计数器** | — | 每 SA 丢弃计数：运维判断 MACsec 健康度的主依据（[3.5 节](../03_secy/3.5_counters.md)） |

---

生成关系图（CAK→KEK/ICK→SAK）见[第二章](../02_key_hierarchy/README.md)；MKA 字段的逐字节位置见[第四章](../04_mka/README.md)。
