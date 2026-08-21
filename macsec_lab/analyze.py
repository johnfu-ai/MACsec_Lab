"""Parse MACsec / MKA PCAPs and emit per-message Markdown."""

from __future__ import annotations

import json
from pathlib import Path

from .crypto import assign_sscis, xpn_default_salt
from .dissect import (
    dissect_eap,
    dissect_macsec,
    dissect_mka,
    field_table,
    one_line,
    xxd,
)
from .keys import (
    EAPOL_TYPE_EAP,
    ETHERTYPE_EAPOL,
    ETHERTYPE_MACSEC,
    IEEE_GCM_KEY_128,
    IEEE_GCM_KEY_256,
    IEEE_SCI,
    LabKeys,
    Peer,
)
from .macsec import XpnPnTracker
from .pcap import read_pcap
from .scenario import XPN_INITIAL_PN64_HIGH


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _peer_from_json(d: dict, side: str, fallback: Peer) -> Peer:
    mac_key = f"{side}_mac"
    if mac_key not in d:
        return fallback
    mac = bytes.fromhex(d[mac_key].replace(":", ""))
    mi = bytes.fromhex(d.get(f"{side}_mi", fallback.mi.hex()))
    prio = int(d.get(f"{side}_ks_priority", fallback.ks_priority))
    name = d.get(f"{side}_name", fallback.name)
    return Peer.make(name, mac, fallback.port_id, prio, mi)


def _lab_keys_from_json(d: dict, fallback: LabKeys) -> LabKeys:
    a = _peer_from_json(d, "a", fallback.a)
    b = _peer_from_json(d, "b", fallback.b)
    return LabKeys(
        cak=bytes.fromhex(d["cak"]),
        ckn=bytes.fromhex(d["ckn"]),
        sak=bytes.fromhex(d["sak"]),
        kek=bytes.fromhex(d["kek"]),
        ick=bytes.fromhex(d["ick"]),
        kn=int(d["kn"]),
        an=int(d["an"]),
        a=a,
        b=b,
        source=d.get("source", fallback.source),
        msk=bytes.fromhex(d["msk"]) if d.get("msk") else b"",
        eap_session_id=bytes.fromhex(d["eap_session_id"]) if d.get("eap_session_id") else b"",
        sak2=bytes.fromhex(d["sak2"]) if d.get("sak2") else b"",
        sak3=bytes.fromhex(d["sak3"]) if d.get("sak3") else b"",
        sak4=bytes.fromhex(d["sak4"]) if d.get("sak4") else b"",
    )


def _load_keys(capture_dir: Path) -> LabKeys:
    keys = LabKeys.default()
    key_file = capture_dir / "keys.json"
    if not key_file.exists():
        return keys
    d = json.loads(key_file.read_text())
    return _lab_keys_from_json(d, keys)


def _load_eap_keys(capture_dir: Path) -> LabKeys:
    eap = LabKeys.eap_default()
    key_file = capture_dir / "keys.json"
    if not key_file.exists():
        return eap
    d = json.loads(key_file.read_text())
    if "eap" in d and isinstance(d["eap"], dict):
        return _lab_keys_from_json(d["eap"], eap)
    return eap


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
    confidentiality_offset: int = 0,
    xpn: dict | None = None,
) -> str:
    et = int.from_bytes(frame[12:14], "big")
    heading = f"## 帧 {n}"
    if comment:
        heading += f" — {comment}"
    parts = [heading, ""]
    if et == ETHERTYPE_EAPOL:
        eapol_type = frame[15] if len(frame) > 15 else -1
        if eapol_type == EAPOL_TYPE_EAP:
            title, fields, parsed = dissect_eap(frame)
            parts += [
                f"**{title}**",
                "",
                f"- 方向：`{_mac(parsed['sa'])}` → `{_mac(parsed['da'])}`（{len(frame)} B）",
                f"- 作用：{comment or 'EAPOL-EAP'}",
                f"- EAPOL Type = `{parsed['eapol_type']}`（0 = EAP-Packet），EAP Code = `{parsed['eap_code']}`",
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
        title, fields, parsed, inner = dissect_macsec(
            frame, sak, sci_a, sci_b, confidentiality_offset, xpn
        )
        tag = parsed["tag"]
        mode_line = f"{tag.mode}" + (f"（confidentiality offset {confidentiality_offset}，前 {confidentiality_offset} 字节明文）" if confidentiality_offset and tag.e else "")
        iv_line = f"- GCM IV = SCI‖PN = `{parsed['iv'].hex()}`"
        if xpn:
            iv_line = (
                f"- XPN IV = (SSCI‖PN64)⊕Salt = `{parsed['iv'].hex()}`"
                f"（SSCI=0x{xpn['ssci']:04x}，PN64=0x{xpn['pn64']:016X}，Salt=`{xpn['salt'].hex()}`）"
            )
        parts += [
            f"**{title}**",
            "",
            f"- 方向：`{_mac(parsed['sa'])}` → `{_mac(parsed['da'])}`（{len(frame)} B）",
            f"- 作用：{comment or 'MACsec 用户帧'}",
            f"- TCI `{tag.tci:#04x}`：{mode_line}；PN = `{tag.pn}`；SCI = `{parsed['sci'].hex()}`",
            iv_line,
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


def _sak_for_frame(frame: bytes, sak: bytes, sak_by_an: dict[int, bytes] | None) -> bytes:
    """Pick the SAK by the frame's AN when a per-AN map is given (rekey story)."""
    if not sak_by_an or len(frame) < 15 or int.from_bytes(frame[12:14], "big") != ETHERTYPE_MACSEC:
        return sak
    return sak_by_an.get(frame[14] & 0x03, sak)


def analyze_pcap(
    path: Path,
    keys: LabKeys,
    comments: list[str],
    sak: bytes | None = None,
    sci_a: bytes | None = None,
    sci_b: bytes | None = None,
    sak_by_an: dict[int, bytes] | None = None,
    confidentiality_offset: int = 0,
    xpn: dict | None = None,
) -> str:
    """xpn, when given, carries the XPN SA context: {"ssci": {mac: ssci},
    "salt": bytes, "trackers": {mac: XpnPnTracker}}. Per MACsec frame the
    analyzer recovers the 64-bit PN the way a receiver does (802.1AE 10.6)
    and derives the nonce (SSCI || PN64) XOR Salt."""
    sak = sak if sak is not None else keys.sak
    sci_a = sci_a if sci_a is not None else keys.a.sci
    sci_b = sci_b if sci_b is not None else keys.b.sci
    pkts = read_pcap(path)
    summary_rows = ["| # | 长度 | SA → DA | 一句话 |", "|---:|---:|---|---|"]
    bodies: list[str] = []
    for i, pkt in enumerate(pkts, 1):
        comment = comments[i - 1] if i - 1 < len(comments) else ""
        sa, da = _mac(pkt.data[6:12]), _mac(pkt.data[0:6])
        frame_sak = _sak_for_frame(pkt.data, sak, sak_by_an)
        frame_xpn = None
        if xpn is not None and int.from_bytes(pkt.data[12:14], "big") == ETHERTYPE_MACSEC:
            src_mac = pkt.data[6:12]
            frame_xpn = {
                "ssci": xpn["ssci"][src_mac],
                "pn64": xpn["trackers"][src_mac].update(int.from_bytes(pkt.data[16:20], "big")),
                "salt": xpn["salt"],
            }
        summary_rows.append(
            f"| {i} | {len(pkt.data)} | `{sa}` → `{da}` | "
            f"{comment or one_line(pkt.data, keys, sci_a, sci_b, frame_sak, confidentiality_offset, frame_xpn)} |"
        )
        bodies.append(
            render_frame(
                i, pkt.data, keys, comment, frame_sak, sci_a, sci_b, confidentiality_offset, frame_xpn
            )
        )
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
    Note over A,B: same CAK / CKN (PSK)
    A->>B: MKA MN=1 hello (claim Key Server)
    B->>A: MKA MN=1 Potential Peer List
    A->>B: MKA MN=2 Distributed SAK + SAK Use tx
    B->>A: MKA MN=2 SAK Use tx+rx
    A->>B: MKA MN=3 both using SAK
    B->>A: MKA MN=3 keepalive
    A->>B: MACsec ICMP PN=1..3 (encrypted)
    B->>A: MACsec ICMP PN=1..3 (encrypted)
    A->>B: MACsec PN=9 ES=1 no SCI
```

分文件报告（同一套解析器）：

- [captures/decoded/01-mka-handshake.md](../captures/decoded/01-mka-handshake.md)
- [captures/decoded/02-macsec-encrypted.md](../captures/decoded/02-macsec-encrypted.md)
- [captures/decoded/03-macsec-integrity-only.md](../captures/decoded/03-macsec-integrity-only.md)
- [captures/decoded/04-ieee-integrity.md](../captures/decoded/04-ieee-integrity.md)
- [captures/decoded/05-ieee-encrypt.md](../captures/decoded/05-ieee-encrypt.md)
- [captures/decoded/11-mka-after-eap.md](../captures/decoded/11-mka-after-eap.md) — EAP-Success 之后的 MKA（Authenticator 为 Key Server）
- [captures/decoded/13-mka-rekey.md](../captures/decoded/13-mka-rekey.md) — SAK 重加密：AN=0 → AN=1 换钥全过程（`mka-rekey.pcap`）

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
        ("mka-after-eap.pcap", "eap", "11-mka-after-eap.md"),
        ("mka-rekey.pcap", "rekey", "13-mka-rekey.md"),
        ("mka-co30.pcap", "co30", "14-mka-co30.md"),
        ("mka-xpn.pcap", "xpn", "17-mka-xpn.md"),
        ("mka-multi-peer.pcap", "multi", "18-mka-multi-peer.md"),
        ("macsec-replay.pcap", "replay", "19-macsec-replay.md"),
        ("macsec-ieee-gcm-aes-256-integrity.pcap", "ieee256", "15-ieee-integrity-256.md"),
        ("macsec-ieee-gcm-aes-256-encrypt.pcap", "ieee256", "16-ieee-encrypt-256.md"),
    ]
    session_text = ""
    for pcap_name, kind, report_name in jobs:
        pcap = capture_dir / pcap_name
        if not pcap.exists():
            continue
        comments = _comments(capture_dir, pcap_name)
        if kind == "ieee":
            text = analyze_pcap(pcap, keys, comments, sak=IEEE_GCM_KEY_128, sci_a=IEEE_SCI, sci_b=IEEE_SCI)
        elif kind == "ieee256":
            text = analyze_pcap(pcap, keys, comments, sak=IEEE_GCM_KEY_256, sci_a=IEEE_SCI, sci_b=IEEE_SCI)
        elif kind == "eap":
            eap_keys = _load_eap_keys(capture_dir)
            text = analyze_pcap(pcap, eap_keys, comments)
        elif kind == "rekey":
            # Data frames carry AN=0 (SAK#1) and AN=1 (SAK#2); pick the key per frame.
            text = analyze_pcap(pcap, keys, comments, sak_by_an={0: keys.sak, 1: keys.sak2})
        elif kind == "co30":
            # SAK#3 on AN=2 with confidentiality offset 30 (inner EtherType+IP+L4 in clear).
            text = analyze_pcap(
                pcap, keys, comments, sak_by_an={2: keys.sak3}, confidentiality_offset=30
            )
        elif kind == "xpn":
            # SAK#4 on AN=3, GCM-AES-XPN-128: nonce (SSCI||PN64) XOR Salt,
            # on-wire PN is only the low 32 bits; per-direction recovery.
            ssci = assign_sscis([keys.a.sci, keys.b.sci])
            text = analyze_pcap(
                pcap,
                keys,
                comments,
                sak_by_an={3: keys.sak4},
                xpn={
                    "ssci": {keys.a.mac: ssci[keys.a.sci], keys.b.mac: ssci[keys.b.sci]},
                    "salt": xpn_default_salt(keys.a.sci),
                    "trackers": {
                        keys.a.mac: XpnPnTracker(high=XPN_INITIAL_PN64_HIGH),
                        keys.b.mac: XpnPnTracker(high=XPN_INITIAL_PN64_HIGH),
                    },
                },
            )
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
