# 附录 B：FAQ 三十六问

按主题分组的问答索引——每条答案给出详细出处（章节/抓包）。入门路径建议：先读[第一章](../01_intro/README.md)建立整体认知，带着问题回来查。

## B.A 概念入门

**Q1. MACsec 和 IPsec 是一回事吗？**
不是。MACsec（IEEE 802.1AE）工作在以太网链路层，逐跳保护；IPsec（IETF）工作在 IP 层，端到端或跨网。同一条流量可以两层都套——详见[第十二章](../12_comparison/README.md)。

**Q2. 为什么叫"逐跳"（hop-by-hop）？**
MACsec 帧到达下一台 SecY（对端交换机/网卡）就被解开还原成普通帧继续转发；保护范围是"一条链路"，不是"一条路径"。

**Q3. MACsec 能加密 ARP/STP/LLDP 吗？**
能加密的：走受控口的一切 EtherType（含 ARP、IP、ICMP）。**例外**：EAPOL/MKA 永远明文走非受控口（[3.1 节](../03_secy/3.1_ports.md)）。注意对端交换机自己要用的控制协议（如 LLDP）加密后它还读得到吗——取决于卸载位置与策略。

**Q4. MACsec 需要 IP 可达吗？**
不需要。MKA 是纯链路层协议（EAPOL 组播），两台交换机对口即可，连 IP 都可以不配——这是它与 WireGuard/IPsec 的根本差异（[12.3 节](../12_comparison/12.3_vs_tls_wireguard.md)）。

**Q5. 什么是 CA？两台设备必须点对点吗？**
CA（Connectivity Association）= 共享同一 CAK/CKN 的成员集合。**不必须点对点**：3 台、10 台设备共享一把 CAK 就是多成员 CA，一把 SAK 全员共用（`mka-multi-peer.pcap`）。

**Q6. MACsec 提供哪些安全服务？**
帧完整性（GCM ICV）、可选机密性（E=1）、CA 内源认证、抗重放（PN 窗口）。不提供：端到端保护、成员间可区分认证、抗流量分析（[9.1 节](../09_attacks/9.1_threat_model.md)）。

**Q7. MKA 和 MACsec 什么关系？**
MKA 是控制面（802.1X）：协商并分发密钥、维持邻居；MACsec 是数据面（802.1AE）：用 MKA 给的 SAK 加密帧。类比：IKEv2 之于 ESP。

**Q8. Wireshark 能直接解开仓库里的加密帧吗？**
能。Preferences → Protocols → MKA 填 CKN/CAK 表（`captures/keys.json`），或对数据面帧在 IEEE 802.1AE 解析器里配 SAK。不配密钥也能读全部 SecTAG 字段。

## B.B 密钥体系

**Q9. 预共享的是 SAK 吗？**
不是。PSK 模式预共享 **CAK + CKN**；SAK 由 Key Server **随机生成**、用 KEK 包裹分发。CAK 从不直接加密用户帧（[第二章](../02_key_hierarchy/README.md)）。

**Q10. KEK 和 ICK 是什么、怎么来的？**
KEK = KDF(CAK, "IEEE8021 KEK", CKN[0:16])，AES-KeyWrap 包 SAK；ICK = KDF(CAK, "IEEE8021 ICK", CKN[0:16])，算 MKPDU 的 ICV。标签是 12 个 ASCII 字节，多一个少一个都不行（见 [2.3 节](../02_key_hierarchy/2.3_kdf.md)）。

**Q11. EAP 模式下 CAK 从哪来？**
EAP-Success 后两端都有 MSK，CAK = KDF(MSK[0:16], "IEEE8021 EAP CAK", mac1‖mac2)，CKN 用 16 字节标签 "IEEE8021 EAP CKN" 同理派生（注意与 KEK/ICK 的 12 字节标签不同）。抓包见 `mka-after-eap.pcap`。

**Q12. Key Server 是怎么选出来的？**
Basic 参数集里宣告优先级（1 字节），**数值最小者当选，平局比 SCI**。PSK 故事里 A(16) 胜 B(32)；EAP 故事里 Authenticator(0) 固定胜（[4.3 节](../04_mka/4.3_ks_election.md)）。

**Q13. 为什么换钥换的是 SAK 而不是 CAK？**
PN 会耗尽（见 Q22），SAK 换起来便宜（一条 MKPDU，双 SA 并存平滑过渡）；CAK 换 = 新 CA = 全部成员重新配置或重认证，代价大。CAK 在线轮换也有标准机制（Distributed CAK）。

**Q14. 一把 SAK 几个方向共用？**
一把 SAK 对应每个成员各一个发送 SA。三个成员的 CA：一把 SAK、三个单向 SC、每个接收方按 (SCI, AN) 建三个 RX SA——三帧各 PN=1 互不冲突（`mka-multi-peer.pcap`）。

**Q15. MKA 有前向保密（PFS）吗？**
**没有**。CAK 是长期秘密，SAK 不经 DH——CAK 泄露就能解开抓包里 Distributed SAK 的包裹、进而解历史流量。要"类 PFS"效果只能勤换 CAK/重认证（[12.2 节](../12_comparison/12.2_vs_ipsec.md) PFS 行）。

**Q16. keys.json 里的密钥能用在生产吗？**
绝对不能。仓库所有密钥是公开演示材料，克隆即视为已泄露（[封面免责声明](../README.md)）。

## B.C 帧格式与抓包

**Q17. SecTAG 里什么时候带 SCI？**
SC=1 显式带 8 字节。点对点两成员 CA 可 ES=1 省掉（IV 仍用 SA‖00-01 还原）；**多成员必须带**。对照 `macsec-lab-encrypted.pcap` 帧 7（ES=1）与 `mka-multi-peer.pcap`（全部 SC=1）。

**Q18. E=1 和 E=0 有什么区别？**
E=1 机密性+完整性（User Data 加密）；E=0 仅完整性（明文可见但不可篡改）。对照 `macsec-lab-encrypted.pcap` / `macsec-lab-integrity-only.pcap` 同一 ICMP 两种模式。

**Q19. confidentiality offset 30 是什么？为什么存在？**
co=30：内层 EtherType+IPv4 头+L4 前 8 字节**只认证不加密**——为了中间设备能读 IP 头做 QoS/ECN。co=50 再多带 20 字节。偏移在 Distributed SAK 里通告，SecTAG 里没有（`mka-co30.pcap`）。

**Q20. PN 不是 32 位吗，XPN 怎么 64 位？**
XPN 套件的 PN 是 64 位，但**线上 SecTAG 仍只带低 32 位**；高 32 位由接收端 SA 状态恢复（大步回跳=回绕进位）。nonce 也换成 (SSCI‖PN64)⊕Salt（`mka-xpn.pcap`）。

**Q21. 同一抓包里两帧 PN 都是 1，是重放吗？**
看 SCI/AN：不同 SC 各自维护 PN 空间，A→B 和 B→A 都从 1 开始；换钥后新 SA 也从 1 重来。同 SCI 同 AN 才谈得上重放（`mka-rekey.pcap`、`macsec-replay.pcap`）。

**Q22. PN 多快会用完？**
2³² 个：1G 小帧约 48 分钟，10G 约 4.8 分钟，100G 约 29 秒——所以高速率必须提前换钥或用 XPN（[6.1 节](../06_lifecycle/6.1_why_rekey.md)的表）。

**Q23. 为什么我的 tcpdump 看到的 MACsec 流量是明文？**
NIC 卸载：抓包点在 SecY 之后（协议栈侧）看到的已是解密帧。想看线上密文要在交换机镜像口/分接器抓（[9.6 节](../09_attacks/9.6_leaks_summary.md)）。

**Q24. Wireshark 过滤器有哪些常用的？**
`mka`、`macsec`、`eapol.type == 5`、`eth.type == 0x88e5`、`mka.param_set_type == 4`（Distributed SAK）、`mka.delay_protect == 1`、`macsec.PN`——完整清单见[10.3 节](../10_lab/10.3_wireshark.md)。

## B.D 部署与运维

**Q25. Linux 上怎么跑 MACsec？**
内核 `CONFIG_MACSEC` 提供 SecY（`ip link add ... type macsec`），wpa_supplicant 提供 KaY/MKA。本仓库写作用的 WSL2 内核没开该选项，所以用 Python 组帧（[附录 C](C_spec.md)）。

**Q26. 网卡必须支持 MACsec 卸载吗？**
不必须（软件 SecY 可跑），但线速（≥10G）实际上依赖 NIC 卸载。买卡看 "MACsec offload" 支持（[第十一章](../11_deployments/README.md)）。

**Q27. MACsec 对 MTU 有什么影响？**
每帧 +24 字节（无 SCI）或 +32 字节（带 SCI）。链路上要调大 MTU 或依赖设备自动处理，否则大帧被丢（与 IPsec/WG 叠加时更明显，[12.4 节](../12_comparison/12.4_choosing.md)）。

**Q28. 交换机上 PAE 组播被丢了怎么办？**
Linux 网桥默认不转发 `01:80:C2:00:00:03`，要写 `group_fwd_mask=8`；本仓库 `make lab` 已内置（[10.5 节](../10_lab/10.5_troubleshooting.md)）。

**Q29. MKA 会话挂了数据面会怎样？**
标准期望 fail-close：约 6 秒没收到对端 MKPDU 判死，受控口关闭，只留 MKA/LLDP。若设备配置成 fail-open 则转发明文——危险（[6.5 节](../06_lifecycle/6.5_liveness.md)、[9.4 节](../09_attacks/9.4_downgrade_dos.md)）。

**Q30. 怎么判断 MACsec 链路健康？**
看每 SA 丢弃计数器：`InPktsBadTag` 涨=密钥不一致/篡改；`InPktsUnknownSCI` 涨=MKA 没起来；`InPktsLate` 涨=乱序超窗或 delay protect 误杀（[3.5 节](../03_secy/3.5_counters.md)的口诀）。

**Q31. 重放窗口开多大合适？**
默认常 0（strict）或几十。窗口越大可容忍乱序越多，但**重放帧能存活的时间也越长**——低时延网络尽量小，高乱序网络配合 delay protect 慎重调（[6.3 节](../06_lifecycle/6.3_replay_window.md)）。

**Q32. delay protect 默认该开吗？**
对时延敏感的链路（金融 DCI）开；乱序/长路径网络慎开——真帧超过 hello 周期（2 s）到达也会被 LLPN 下沿误杀（`mka-delay-protect.pcap`、[6.4 节](../06_lifecycle/6.4_delay_protect.md)）。

## B.E 对比与选型

**Q33. 有了 TLS 为什么还要 MACsec？**
TLS 保护"连接"，MACsec 保护"链路上的一切"（含 ARP、未加密协议、主机间管理流量）；且 MACsec 线速硬件卸载、对上层完全透明。两者互补（[12.3 节](../12_comparison/12.3_vs_tls_wireguard.md)）。

**Q34. MACsec 和 802.1X 是什么关系？**
802.1X 是父标准：定义 EAPOL 接入认证（2001 起）和 MKA（2010 起）。"端口接不接入"用 EAP，"接入后链路加不加密"用 MKA+MACsec。EAP 的 MSK 还能派生 CAK（`mka-after-eap.pcap`）。

**Q35. 哪些真实场景在用 MACsec？**
运营商/DCI 链路、数据中心 Spine-Leaf、金融同城互联、5G 回传、云厂商内网——案例与厂商支持见[第十一章](../11_deployments/README.md)。

**Q36. 学 MACsec 的最佳顺序？**
①[第一章](../01_intro/README.md)看故事线 → ②[第二章](../02_key_hierarchy/README.md)弄懂五个密钥对象 → ③[第三章](../03_secy/README.md)建立收发模型 → ④[第五章](../05_wire_format/README.md)逐帧读一条真实会话 → ⑤[第六章](../06_lifecycle/README.md)+`mka-rekey.pcap` 理解换钥 → ⑥[第七章](../07_cipher_suites/README.md)+`mka-xpn.pcap` 摸到 XPN → ⑦[第九章](../09_attacks/README.md)建立攻防视角。配套 `make test` 改任何常量看哪条断言挂——挂得越早的概念越重要。
