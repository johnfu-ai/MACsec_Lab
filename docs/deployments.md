# 真实世界的 MACsec：Linux、交换机、网卡与典型场景

实验室教你协议长什么样；本文教你**生产上怎么落地**。全部基于公开文档可验证的内容；厂商 CLI 只给"形状"，逐字语法以各家配置指南为准。

## 1. Linux：免费的全栈（wpa_supplicant + ip macsec）

Linux 内核自带 SecY（`CONFIG_MACSEC`），wpa_supplicant 自带 KaY（MKA）。先确认内核支持：

```bash
modinfo macsec           # 有输出 = 内核带 MACsec 模块
# 或: grep CONFIG_MACSEC /boot/config-$(uname -r)
```

> 本仓库写作用的 WSL2 内核 `CONFIG_MACSEC` 未开——这正是仓库用 Python 组帧 + AF_PACKET 回放的原因（见 [spec.md](spec.md)）。

### PSK 模式最小配置（两端对称）

```ini
# /etc/wpa_supplicant/macsec-a.conf —— 概念示例，逐项含义见 wpa_supplicant(8) MACsec 小节
ap_scan=0
eapol_flags=0
network={
    key_mgmt=NONE
    macsec_policy=1          # 该端口必须 MACsec
    macsec_integ_only=0      # 0=加密+完整性， 1=仅完整性
    macsec_replay_protect=1
    macsec_replay_window=32
    mka_cak=00112233445566778899aabbccddeeff   # 128-bit CAK（32 个 hex）——演示值！
    mka_ckn=4d41435345432d4c41422d434b4e3031   # CKN 的 hex（这是 ASCII "MACSEC-LAB-CKN01"）
}
```

```bash
wpa_supplicant -i eth0 -D wired -c macsec-a.conf &   # 对端同样，CKN/CAK 相同
ip link show type macsec                               # 会话起来后出现 macsec 设备
```

与仓库的对应关系：`mka_cak`/`mka_ckn` 就是 `captures/keys.json` 里的 `cak`/`ckn`；wpa_supplicant 内部做的派生（KEK/ICK/SAK 分发）即 [key-hierarchy.md](key-hierarchy.md) 那张图。

### 手工 SecY（不要 wpa_supplicant，自己管 SAK）

```bash
ip link add link eth0 macsec0 type macsec
ip macsec add macsec0 tx sa 0 pn 1 on key 01 <SAK-hex-32字节>
ip macsec add macsec0 rx address 02:00:00:00:00:0b port 1
ip macsec add macsec0 rx address 02:00:00:00:00:0b port 1 sa 0 pn 1 on key 01 <对端方向同钥>
ip link set macsec0 up
ip macsec show        # SA/PN/统计
```

这等价于实验室里"跳过 MKA、直接把 SAK 装进 SecY"——抓包看数据面与 `session-full.pcap` 一致。

### 性能

内核软件路径单核几 Gbps 量级。万兆以上要 **NIC 卸载**（下文），否则 CPU 先到顶。

## 2. 交换机/路由器上的 MACsec（商业实现）

| 厂商路线 | 说明 |
|---|---|
| Cisco Catalyst/Nexus | MACsec+MKA 最早商用（TrustSec 家族）；PSK（keychain：CKN+CK 成对）或 802.1X 会话密钥；常见于交换机互联与下联 |
| Arista | 线速 MACsec（GCM-AES-128/256，部分平台 XPN） |
| Juniper MX/PTX | 部分 MPC/线卡 inline MACsec；PSK 与 802.1X |
| HPE/华为等 | 运营商导向，E-Line/E-LAN 侧加密 |

PSK 配置的**共同形状**（各家语法不同）：

```
key-chain（或等价物）:
  CKN: <名字>   CK: <CAK>           # = mka_ckn / mka_cak
interface:
  macsec enable
  key-server-priority <小者优先>     # 本仓库 A=16 B=32 的那场比赛
  cipher <GCM-AES-128/256>           # 见 cipher-suites.md
  confidentiality-offset <0|30|50>   # 运营商 ECMP 场景常见 30
  replay-window <N>
  fail-mode <secure|open>            # fail-close vs fail-open，见 lifecycle.md
```

## 3. 网卡（NIC）卸载

| 硬件 | MACsec 能力 |
|---|---|
| Intel E810 | inline MACsec（ice 驱动），四套件 |
| NVIDIA/Mellanox ConnectX-6 Dx / ConnectX-7 | inline MACsec + IPsec，25G–400G |
| 交换 ASIC（Broadcom Tomahawk 系列等） | 线速 MACsec，DC/运营商平台常用 |

判断一台机器有没有卸载：`ethtool -k <iface> | grep macsec`（`macsec-hw-offload` 类条目）。

## 4. 典型部署场景

### A. 交换机互联 / 运营商以太网（最经典）

.metro 以太网 E-Line/E-LAN、接入环、微波回传：两台交换机之间一条 MACsec 链路，中间传输网只见密文。常配 **co=30**（转发设备要读 IP 头做 ECMP/哈希，见 [macsec-protocol-analysis.md](macsec-protocol-analysis.md) §4b）。

### B. 数据中心

叶脊（spine-leaf）underlay 链路加密：host–leaf 或 leaf–spine。SONiC 把 MACsec 作为特性支持（SAI + orchagent）；AI/云集群的 east-west 流量加密在 100G+ 必须硬件卸载 + **XPN**（32-bit PN 几十秒烧完，见 [lifecycle.md](lifecycle.md)）。

### C. 路由器点对点互联

两台路由器经 DWDM/暗纤互联，MACsec 保护整段以太网；与 IPsec 叠加即"链路加密 + 端到端加密"（见 [vs-ipsec.md](vs-ipsec.md)）。

### D. 企业有线端口（较少）

802.1X 成功后用会话密钥跑 MKA（EAP-MSK → CAK 路线，本仓库 `mka-after-eap.pcap`）。现实里用户端口更多只做认证不做加密；真要加密时要求网卡/驱动配合（Windows 内置 MACsec 支持 802.1X AE；macOS 不做有线 MACsec）。

## 5. 运维清单（踩坑汇总）

1. **MTU**：MACsec 开销 = SecTAG 8/16 + ICV 16 + 对齐 padding，典型 **+16~+32 字节**。两端与中间设备必须同时升 jumbo，否则大帧黑洞。
2. **控制协议明文**：LLDP/LACP/STP/CFM 不走 MACsec（它们是链路作用域协议）。策略上要允许这些 EtherType，其余丢弃。
3. **fail-close 还是 fail-open**：MKA 挂掉后链路是断还是明文透传？监管场景选 fail-close（`macsec_policy=1` 等价）；测试网才考虑 open。
4. **重放窗口 vs 微突发**：窗口太小会在乱序/微突发时丢合法帧；先看 `ip macsec show` 的 replay 计数再调。
5. **PSK 的运营成本**：N 条链路 N 套 CAK，轮换靠人。规模上去改 802.1X（EAP）动态发钥，或至少 keychain 里预排两代密钥。
6. **监控什么**：MKA 会话状态（对端 alive）、PN 增速（多久换钥）、ICV 校验失败计数（错误钥匙/线路误码）、明文帧计数（策略泄漏）。
7. **抓包排障**：镜像口看到的是密文属正常；要么在 SecY 之内抓（解密后），要么用 Wireshark + SAK 解密（见 [wireshark-howto.md](wireshark-howto.md)）。
8. **和 Q-in-Q / 隧道的叠层顺序**：外层 VLAN tag 在 MACsec 之外时是明文；规划 Ethertype 顺序（0x88E5 在内层），两端一致。

## 6. 从仓库走向真实网络的学习路径

```
看懂帧与钥（本仓库 docs/ + pcaps）
  → make lab 回放到 veth（scripts/run-lab.sh）
  → 有 CONFIG_MACSEC 的机器上跑 wpa_supplicant + ip macsec
  → 两台真交换机间配 PSK MACsec，抓 MKA 与 0x88E5 对照 keys.json 的派生
```
