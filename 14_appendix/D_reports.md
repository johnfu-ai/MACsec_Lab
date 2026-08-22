# 附录 D：抓包字段级报告（make generate 生成）

本仓库自带的解析器为每份参考抓包生成字段级报告：**总览表 + 逐字段偏移表 + 十六进制**。解析不依赖 Wireshark 密钥表——ICV 逐一校验、SAK 当场解包、内层 IPv4 直接展开，因此报告本身就是"这些帧密码学有效"的证据。

报告由 `make generate` 写入 `captures/decoded/`，与左侧目录中的 D.01–D.15 对应。下表给出每份的看点：

| 报告 | 看点 |
|---|---|
| [D.01 MKA 握手（PSK）](../captures/decoded/01-mka-handshake.md) | PSK 握手 6 帧：hello → 选 KS → 分发 SAK → 双方 SAK Use |
| [D.02 MACsec 加密模式](../captures/decoded/02-macsec-encrypted.md) | 同一 ICMP 的加密模式（E=1 C=1） |
| [D.03 MACsec 仅完整性模式](../captures/decoded/03-macsec-integrity-only.md) | 同一 ICMP 的仅完整性模式（E=0 C=0），内层明文可见 |
| [D.04 IEEE 向量：完整性](../captures/decoded/04-ieee-integrity.md) | IEEE GCM-AES-128 官方完整性向量帧 |
| [D.05 IEEE 向量：加密](../captures/decoded/05-ieee-encrypt.md) | IEEE GCM-AES-128 官方机密性向量帧 |
| [D.06 完整会话 13 帧](../captures/decoded/06-session-full.md) | 完整会话故事线（与 [5.3](../05_wire_format/5.3_control_plane_frames.md)/[5.4](../05_wire_format/5.4_data_plane_frames.md) 节同源） |
| [D.07 EAP 之后的 MKA](../captures/decoded/11-mka-after-eap.md) | EAP-Success 之后：CAK 从 MSK 派生、Authenticator 当 KS |
| [D.08 SAK 换钥](../captures/decoded/13-mka-rekey.md) | SAK 换钥全过程（AN=0 → AN=1 → 旧钥退役） |
| [D.09 Confidentiality Offset 30](../captures/decoded/14-mka-co30.md) | co=30：前 30 字节只认证不加密 |
| [D.10 IEEE 向量：完整性 256](../captures/decoded/15-ieee-integrity-256.md) | IEEE GCM-AES-256 官方向量（完整性） |
| [D.11 IEEE 向量：加密 256](../captures/decoded/16-ieee-encrypt-256.md) | IEEE GCM-AES-256 官方向量（机密性） |
| [D.12 XPN 套件](../captures/decoded/17-mka-xpn.md) | 套件 ID 进 Distributed SAK，PN64 越过 2³²、线上 PN 回绕而不换钥 |
| [D.13 多成员 CA](../captures/decoded/18-mka-multi-peer.md) | 3 节点共享 CAK、一个 KS 分发一把 SAK、三个 SC 各自 PN |
| [D.14 重放窗口四裁决](../captures/decoded/19-macsec-replay.md) | 乱序接受、原样重放帧被丢弃（ICV 依然有效） |
| [D.15 Delay Protect](../captures/decoded/20-mka-delay-protect.md) | SAK Use 宣告 LLPN 下沿，被截留的帧延迟重放必弃 |

同目录下还有若干 `*-tshark-*.txt` 文本树（tshark 对同一抓包的展开输出），可与本仓库解析器的报告互相印证。

这些报告是**生成物**：`make clean` 会删除 `captures/decoded/`（同时也会删掉书稿构建所依赖的这些页面），`make generate` 会原样重建。日常工作流是改代码后 `make verify`——它先跑测试再重建全部产物。
