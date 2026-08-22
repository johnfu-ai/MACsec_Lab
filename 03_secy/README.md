# 第三章 SecY 数据面：一帧的旅程

第二章讲清了钥匙从哪里来；本章讲这些钥匙在哪里被使用。SecY（MAC Security Entity，802.1AE Clause 9/10）是 MACsec 数据面的执行者：发送方向它"保护"帧，接收方向它"校验并去保护"帧。抓包只能告诉你线上长什么样，而 SecY 的处理模型能告诉你**两端设备里发生了什么**——包括那些在抓包上根本看不到、却是排障关键的内部行为。

本章主要内容包括：

- **3.1 受控口与非受控口**：桥接模型里的两个逻辑口，以及为什么非受控口必须永远放行 EAPOL
- **3.2 发送路径：一帧如何被保护**：protect 六步流水线，逐步对照实验室实现
- **3.3 接收路径：一帧要过几道关**：validate 五道关与"静默丢弃"原则
- **3.4 Validate Frames：未保护帧怎么办**：strict / checked / disabled 三种策略与 fail-open 风险
- **3.5 丢弃是静默的：计数器与排障**：每 SA/SC 计数器、排查口诀与仓库代码对应

通过本章的学习，读者将能够在心里"单步执行"一帧穿过 MACsec 的全过程，并能根据计数器读数判断链路的问题出在密钥、会话还是时延上。

```mermaid
graph LR
    TX["transmit: protect 6 steps"] --> WIRE["wire: 0x88E5 frames"]
    WIRE --> RX["receive: validate 5 gates"]
    KEYS["SAK from MKA"] --> TX
    KEYS --> RX
    RX -->|"silent drop on any failure"| DROP["counters tell the story"]
```
