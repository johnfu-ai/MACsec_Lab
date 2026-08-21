# 攻击面分析：MACsec 防什么、不防什么

学习笔记（非渗透指南）。每一条都给出原理 → **实验室证据**（可复现的抓包/测试）→ 真实部署的缓解。先给结论表，再逐条展开。

## 0. 威胁模型与安全目标

MACsec 假设的对手：**能在链路上收发帧的任何人**（分接器、恶意邻居、被攻陷的中间交换机口）。它的安全目标按 802.1AE：

| 提供 | 不提供 |
|---|---|
| 帧完整性（GCM tag，16 B） | 端到端保护（逐跳，止于下一个 SecY） |
| 可选机密性（E=1，含 co 偏移） | 匿名性/抗流量分析（帧长、时序可见；见 §11） |
| CA 内源认证（共享 SAK ⇒ 帧来自 CA 成员） | **成员间**的可区分认证（组密钥的固有限制，见 §8） |
| 抗重放（PN 窗口 + Delay Protect） | 可用性（MKA/控制面可被打，见 §9） |

## 1. GCM nonce 复用（最致命）

**原理**：GCM 的安全性依赖 (key, IV) 绝不重复。同一 SAK 内 IV = SCI‖PN，因此**同一 SC 里 PN 复用** = nonce 复用 → 攻击者可恢复认证子密钥、伪造任意帧（"forbidden attack"）。MACsec 的整个 PN 生命周期管理（[lifecycle.md](lifecycle.md) §1：2³² 用尽前必须换钥；每方向独立 SC 独立计数）就是为防它设计的。
**实验室证据**：`tests/test_protocol.py` 的 XPN 用例——错 salt/错 SSCI 构造出不同 nonce 即验证失败；PN 空间管理见 `mka-xpn.pcap`（64 位 PN 跨 2³²）。
**缓解**：换钥阈值留余量（在 PN 耗尽前分 发新 SAK）；高速率用 XPN；永不手工重置 PN。

## 2. 经典重放

**原理**：原样重发合法帧（ICV 天然有效）。防御完全是**接收端策略**：重放窗口四裁决（[lifecycle.md](lifecycle.md) §3.1）。
**实验室证据**：`macsec-replay.pcap` 帧 6——帧 3 的逐字节拷贝、ICV 通过，被"低于窗口下沿"丢弃。
**缓解**：窗口别开太大（重放帧存活时间 ∝ 窗口）；`InPktsLate` 计数器监控。

## 3. 延迟重放（截留后择机放出）

**原理**：§2 的窗口有盲区——**被截留从未到达**的帧不受"已见过"约束，经典窗口会无限期接受它。Delay Protect 用 SAK Use 宣告的 LLPN 把重放延迟限死在一个 hello 周期（约 2 s）内。
**实验室证据**：`mka-delay-protect.pcap`——被拦下的 PN=1 字节级合法且"未见过、在窗口内"，经典窗口必收；LPN 下沿让它作废。
**缓解**：低时延网络开 delay protect；高时延/乱序路径慎开（真帧也会被误杀，`InPktsLate` 上涨）。

## 4. 明文降级与 fail-open

**原理**：攻击不在密码学，在**策略回退**——设备配置成"MKA 起不来就明文转发"（fail-open）或 validate-frames=disabled（不校验 ICV），加密就退化成装饰。攻击者只需**打死 MKA**（见 §9）就能触发回退。
**实验室证据**：[secy-processing.md](secy-processing.md) §4 的三模式表（strict/checked/disabled）；[lifecycle.md](lifecycle.md) §5 的 fail-close/fail-open 行为。
**缓解**：机密性链路一律 strict + fail-close；监控受控口状态而非只看链路 up。

## 5. CAK 离线暴力（PSK 弱口令）

**原理**：PSK 模式下 KEK/ICK 都从 CAK 派生，而 MKPDU 的 ICV 校验**不需要任何在线交互**——攻击者抓一条 MKPDU 就能离线逐个试 CAK 猜测（等价于 WPA-PSK 的离线字典环境）。
**实验室证据**：`parse_eapol_mka(raw, ick)` 只凭抓包+候选 ICK 即可判 ICV 真伪——把它套进循环就是暴力验证器（别这么做）。
**缓解**：CAK 用 128 bit 随机数（不是人类口令）；或改走 EAP 模式（CAK 从 MSK 派生，`mka-after-eap.pcap`）；定期轮换。

## 6. CKN/CAK 配错与"假会话"

**原理**：CAK 对不上 MKA 根本起不来（ICV 全挂），但配置漂移常引发更隐蔽的问题：同端口两套 CKN 各自为政、或对端 fail-open 明文。**现象是静默丢帧**，不是报错。
**实验室证据**：`keys.json` 里 PSK 与 EAP 两套 CKN 并存——同一对 MAC 可以属于两个不同 CA。
**缓解**：`InPktsBadTag`/`InPktsUnknownSCI` 告警；配置管理盯 CKN 一致性。

## 7. 在路径 DoS（控制面）

**原理**：MKA 走明文组播（`01:80:C2:00:00:03`），任何人可发垃圾 MKPDU。好在 MN 反重放 + ICV 让伪造帧无效；但**丢弃合法帧**（选择性丢 MKA 不丢数据）6 秒就能让会话判死 → 受控口关闭（fail-close 时是断流 DoS；fail-open 时是降级攻击的跳板，见 §4）。SAK 分发帧被丢可拖延换钥直到 PN 耗尽。
**实验室证据**：`mka-rekey.pcap` 的换钥三段式——任一步丢失即停滞；[mka-reference.md](mka-reference.md) §2 的 6 s 判死。
**缓解**：MKA 与数据同链路的监控（keepalive 丢失率）；关键链路双路径。

## 8. 组密钥的固有问题：成员互相不可区分

**原理**：同一 CA 全员共享 SAK——**任何一个成员都能伪造其他成员的帧**（填别人的 SCI 即可），接收方无法区分帧真正来自哪个成员。这在 `mka-multi-peer.pcap` 的拓扑下是结构性的：一把 SAK，三个源。
**实验室证据**：`mka-multi-peer.pcap` 帧 8-10——同钥不同 SCI；把帧 8 的 SA/SCI 改成 C 的再重算 ICV（C 也知道 SAK）在密码上完全合法。
**缓解**：需要成员级问责就要**两两成对 CA**（N×(N-1)/2 个 CAK）或上层认证（如 IPsec/应用层）；这是 MACsec 与"每对一会话"协议（TLS/WireGuard）的根本差异（[vs-ipsec.md](vs-ipsec.md)）。

## 9. co 偏移的明文泄露面

**原理**：confidentiality offset 30/50 让内层 IP 头（及 co50 时的更多头部）明文可见——为的是中间设备能读 QoS/路由信息，代价是元数据泄露（地址、DSCP、流规模）。
**实验室证据**：`mka-co30.pcap`——内层 IPv4 源/目的在密文里直接可读（仍在 ICV 保护下，不可篡改）。
**缓解**：机密性敏感场景用 co=0；co>0 只在有明确中间盒需求时开。

## 10. 捕获点 vs NIC 卸载（观测误差，也是取证风险）

**原理**：MACsec 常在 NIC 卸载——tcpdump 在协议栈上抓到的可能已是**解密后**的帧，"看起来没加密"；反之在交换机口抓到的全是密文。取证/审计时必须确认捕获点在 SecY 之前还是之后。
**实验室证据**：本仓库抓包全部是**线上的密文侧**（AF_PACKET 回放，[topology.md](topology.md)）。
**缓解**：审计用交换机镜像口/分接器；`macsec.decrypted_data` 字段说明 Wireshark 配了 SAK。

## 11. 元数据与流量分析

**原理**：MACsec 不隐藏帧长、时序、流量模式——交换机/中间人仍可做流量分析。802.1AEdk（2023，MAC Privacy Protection）才补填充/整形。
**缓解**：目前主要靠上层（WireGuard/TLS padding）；见 [standards-map.md](standards-map.md) 时间线。

## 12. 总结：防线分层

| 层 | 防什么 | 破了会怎样 |
|---|---|---|
| GCM ICV | 篡改/伪造（含 co 明文前缀） | §1 nonce 复用时整体崩塌 |
| PN 窗口 | 原样重放 | §3 截留延迟重放绕过 |
| Delay Protect LPN | 截留延迟重放 | 高时延下误杀真帧 |
| validate=strict + fail-close | 明文降级 | §4/§7 组合成断流或降级 |
| CAK 保密 + 随机 | 离线暴力/冒充成员 | §5/§8 |
| 组网设计 | 逐跳信任边界 | hop-by-hop 之外裸奔 |

> Lab keys in `captures/keys.json` are intentionally public. 本文档用于理解防线构成——攻防研究请在自有实验环境进行。
