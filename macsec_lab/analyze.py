"""Parse MACsec / MKA PCAPs and emit per-message Markdown."""

from __future__ import annotations

import json
from pathlib import Path

from .dissect import (
    dissect_macsec,
    dissect_mka,
    field_table,
    one_line,
    xxd,
)
from .keys import ETHERTYPE_EAPOL, ETHERTYPE_MACSEC, IEEE_GCM_KEY_128, IEEE_SCI, LabKeys
from .pcap import read_pcap


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _load_keys(capture_dir: Path) -> LabKeys:
    keys = LabKeys.default()
    key_file = capture_dir / "keys.json"
    if not key_file.exists():
        return keys
    d = json.loads(key_file.read_text())
    return LabKeys(
        cak=bytes.fromhex(d["cak"]),
        ckn=bytes.fromhex(d["ckn"]),
        sak=bytes.fromhex(d["sak"]),
        kek=bytes.fromhex(d["kek"]),
        ick=bytes.fromhex(d["ick"]),
        kn=int(d["kn"]),
        an=int(d["an"]),
        a=keys.a,
        b=keys.b,
    )


def _comments(capture_dir: Path, pcap_name: str) -> list[str]:
    idx = capture_dir / "frame-index.json"
    if not idx.exists():
        return []
    data = json.loads(idx.read_text())
    return list(data.get(pcap_name, []))


def render_frame(
    n: int,
    frame: bytes,
    keys: LabKeys,
    comment: str,
    sak: bytes,
    sci_a: bytes,
    sci_b: bytes,
) -> str:
    et = int.from_bytes(frame[12:14], "big")
    heading = f"## 帧 {n}"
    if comment:
        heading += f" — {comment}"
    parts = [heading, ""]
    if et == ETHERTYPE_EAPOL:
        title, fields, parsed = dissect_mka(frame, keys)
        b = parsed["basic"]
        parts += [
            f"**{title}**",
            "",
            f"- 方向：`{_mac(parsed['sa'])}` → `{_mac(parsed['da'])}`（{len(frame)} B）",
            f"- 作用：{comment or 'MKA PDU'}",
            f"- Key Server 标志 = `{b.key_server}`，优先级 = `{b.ks_priority}`，MN = `{b.actor_mn}`",
            f"- ICV 校验 = `{parsed['icv_ok']}`（AES-CMAC(ICK, DA‖SA‖0x888E‖EAPOL−ICV)）",
            "",
            "### 逐字段（相对帧起始偏移）",
            "",
            field_table(fields),
            "",
            "### 十六进制",
            "",
            "```",
            xxd(frame),
            "```",
            "",
        ]
        return "\n".join(parts)
    if et == ETHERTYPE_MACSEC:
        title, fields, parsed, inner = dissect_macsec(frame, sak, sci_a, sci_b)
        tag = parsed["tag"]
        parts += [
            f"**{title}**",
            "",
            f"- 方向：`{_mac(parsed['sa'])}` → `{_mac(parsed['da'])}`（{len(frame)} B）",
            f"- 作用：{comment or 'MACsec 用户帧'}",
            f"- TCI `{tag.tci:#04x}`：{tag.mode}；PN = `{tag.pn}`；SCI = `{parsed['sci'].hex()}`",
            f"- GCM IV = SCI‖PN = `{parsed['iv'].hex()}`",
            f"- AAD = {parsed['aad_desc']}",
            f"- ICV 校验 = `{parsed['icv_ok']}`",
            "",
            "### 线上字段（相对帧起始偏移）",
            "",
            field_table(fields),
            "",
        ]
        if inner:
            parts += [
                "### 解密后 User Data（相对 User Data 起始）",
                "",
                field_table(inner),
                "",
            ]
            raw = parsed["user_data"]
            parts += [
                "```",
                xxd(raw),
                "```",
                "",
            ]
        parts += [
            "### 整帧十六进制",
            "",
            "```",
            xxd(frame),
            "```",
            "",
        ]
        return "\n".join(parts)
    return "\n".join(parts + [f"未知 EtherType `{et:#06x}`", ""])


def analyze_pcap(
    path: Path,
    keys: LabKeys,
    comments: list[str],
    sak: bytes | None = None,
    sci_a: bytes | None = None,
    sci_b: bytes | None = None,
) -> str:
    sak = sak if sak is not None else keys.sak
    sci_a = sci_a if sci_a is not None else keys.a.sci
    sci_b = sci_b if sci_b is not None else keys.b.sci
    pkts = read_pcap(path)
    summary_rows = ["| # | 长度 | SA → DA | 一句话 |", "|---:|---:|---|---|"]
    bodies: list[str] = []
    for i, pkt in enumerate(pkts, 1):
        comment = comments[i - 1] if i - 1 < len(comments) else ""
        sa, da = _mac(pkt.data[6:12]), _mac(pkt.data[0:6])
        summary_rows.append(
            f"| {i} | {len(pkt.data)} | `{sa}` → `{da}` | {comment or one_line(pkt.data, keys, sci_a, sci_b)} |"
        )
        bodies.append(render_frame(i, pkt.data, keys, comment, sak, sci_a, sci_b))
    header = [
        f"# 逐帧解析 — `{path.name}`",
        "",
        f"共 **{len(pkts)}** 帧。每条消息包含：作用说明、偏移字段表、十六进制；MACsec 另附解密后的内层 IPv4/ICMP。",
        "",
        "## 总览",
        "",
        "\n".join(summary_rows),
        "",
    ]
    return "\n".join(header) + "\n" + "\n".join(bodies)


def protocol_analysis_doc(session_md: str) -> str:
    intro = """# 协议消息逐帧解析

本文由 `make generate` 根据 `captures/session-full.pcap` 自动生成，覆盖实验室一次完整会话里的 **每一条** MKA 与 MACsec 消息。

阅读顺序建议：先看总览表，再按帧号对照 Wireshark（过滤 `mka || macsec`）。密钥见 `captures/keys.json`（演示密钥，公开）。

```mermaid
sequenceDiagram
    autonumber
    participant A as node-a KS prio 16
    participant B as node-b prio 32
    A->>B: MKA MN=1 hello（自称 Key Server）
    B->>A: MKA MN=1 Potential Peer List
    A->>B: MKA MN=2 Distributed SAK + SAK Use tx
    B->>A: MKA MN=2 SAK Use tx+rx
    A->>B: MKA MN=3 双方都在用 SAK
    B->>A: MKA MN=3 keepalive
    A->>B: MACsec ICMP PN=1..3（加密）
    B->>A: MACsec ICMP PN=1..3（加密）
    A->>B: MACsec PN=9 ES=1 无 SCI
```

分文件报告（同一套解析器）：

- [captures/decoded/01-mka-handshake.md](../captures/decoded/01-mka-handshake.md)
- [captures/decoded/02-macsec-encrypted.md](../captures/decoded/02-macsec-encrypted.md)
- [captures/decoded/03-macsec-integrity-only.md](../captures/decoded/03-macsec-integrity-only.md)
- [captures/decoded/04-ieee-integrity.md](../captures/decoded/04-ieee-integrity.md)
- [captures/decoded/05-ieee-encrypt.md](../captures/decoded/05-ieee-encrypt.md)

格式与密钥体系背景：[mka-protocol-analysis.md](mka-protocol-analysis.md)、[macsec-protocol-analysis.md](macsec-protocol-analysis.md)。

---

"""
    lines = session_md.splitlines()
    if lines and lines[0].startswith("# "):
        lines = lines[1:]
    while lines and lines[0] == "":
        lines = lines[1:]
    return intro + "\n".join(lines) + "\n"


def write_reports(capture_dir: Path, out_dir: Path, docs_dir: Path | None = None) -> list[Path]:
    keys = _load_keys(capture_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    jobs = [
        ("mka-handshake.pcap", "lab", "01-mka-handshake.md"),
        ("macsec-lab-encrypted.pcap", "lab", "02-macsec-encrypted.md"),
        ("macsec-lab-integrity-only.pcap", "lab", "03-macsec-integrity-only.md"),
        ("macsec-ieee-gcm-aes-128-integrity.pcap", "ieee", "04-ieee-integrity.md"),
        ("macsec-ieee-gcm-aes-128-encrypt.pcap", "ieee", "05-ieee-encrypt.md"),
        ("session-full.pcap", "lab", "06-session-full.md"),
    ]
    session_text = ""
    for pcap_name, kind, report_name in jobs:
        pcap = capture_dir / pcap_name
        if not pcap.exists():
            continue
        comments = _comments(capture_dir, pcap_name)
        if kind == "ieee":
            text = analyze_pcap(pcap, keys, comments, sak=IEEE_GCM_KEY_128, sci_a=IEEE_SCI, sci_b=IEEE_SCI)
        else:
            text = analyze_pcap(pcap, keys, comments)
        dest = out_dir / report_name
        dest.write_text(text)
        written.append(dest)
        if pcap_name == "session-full.pcap":
            session_text = text

    if docs_dir is not None and session_text:
        docs_dir.mkdir(parents=True, exist_ok=True)
        doc = docs_dir / "protocol-analysis.md"
        doc.write_text(protocol_analysis_doc(session_text))
        written.append(doc)
    return written
