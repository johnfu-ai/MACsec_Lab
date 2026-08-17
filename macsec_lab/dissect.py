"""Offset-level field maps for every MKA / MACsec frame."""

from __future__ import annotations

from dataclasses import dataclass

from .keys import (
    ETHERTYPE_EAPOL,
    ETHERTYPE_IPV4,
    ETHERTYPE_MACSEC,
    LabKeys,
    PAE_GROUP_ADDR,
)
from .macsec import parse_frame
from .mka import (
    BasicParamSet,
    DistributedSak,
    PeerList,
    SakUse,
    _read_body_len,
    iter_mkpdu_sets,
    parse_eapol_mka,
)

CAP_NAMES = {
    0: "未实现 MACsec",
    1: "仅完整性",
    2: "完整性+机密性，offset 0",
    3: "完整性+机密性，offset 0/30/50",
}

ICMP_TYPES = {0: "Echo Reply", 8: "Echo Request", 3: "Destination Unreachable"}


@dataclass
class Field:
    offset: int
    length: int
    name: str
    value: str
    note: str = ""
    hex: str = ""


def _hx(b: bytes) -> str:
    return b.hex()


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _ip(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def xxd(data: bytes) -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        left = " ".join(f"{b:02x}" for b in chunk[:8])
        right = " ".join(f"{b:02x}" for b in chunk[8:])
        hexpart = f"{left}  {right}".rstrip()
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {hexpart:<48}  {ascii_}")
    return "\n".join(lines)


def field_table(fields: list[Field]) -> str:
    lines = [
        "| Offset | Len | Hex | Field | Value | 说明 |",
        "|---:|---:|---|---|---|---|",
    ]
    for f in fields:
        hx = f.hex if f.hex else ""
        if len(hx) > 48:
            hx = hx[:32] + "…" + hx[-8:]
        lines.append(
            f"| {f.offset} | {f.length} | `{hx}` | {f.name} | `{f.value}` | {f.note} |"
        )
    return "\n".join(lines)


def _add(fields: list[Field], data: bytes, off: int, length: int, name: str, value: str, note: str = "") -> int:
    fields.append(Field(off, length, name, value, note, _hx(data[off : off + length])))
    return off + length


def ethernet_fields(frame: bytes, etype_note: str) -> list[Field]:
    fields: list[Field] = []
    da, sa = frame[0:6], frame[6:12]
    da_note = "PAE 组播（MKA 必须用组地址）" if da == PAE_GROUP_ADDR else "对端单播 MAC"
    _add(fields, frame, 0, 6, "DA", _mac(da), da_note)
    _add(fields, frame, 6, 6, "SA", _mac(sa), "发送方 MAC")
    et = int.from_bytes(frame[12:14], "big")
    _add(fields, frame, 12, 2, "EtherType", f"{et:#06x}", etype_note)
    return fields


def tci_bits(tci: int) -> str:
    return (
        f"V={(tci >> 7) & 1} ES={(tci >> 6) & 1} SC={(tci >> 5) & 1} "
        f"SCB={(tci >> 4) & 1} E={(tci >> 3) & 1} C={(tci >> 2) & 1} AN={tci & 3}"
    )


def dissect_ipv4_user(user: bytes, base: int = 0) -> list[Field]:
    """Parse original EtherType + IPv4 + ICMP (lab User Data)."""
    fields: list[Field] = []
    if len(user) < 2:
        return fields
    et = int.from_bytes(user[0:2], "big")
    _add(fields, user, base + 0, 2, "原 EtherType", f"{et:#06x}", "被保护的内层类型，不是 0x88E5")
    if et != ETHERTYPE_IPV4 or len(user) < 22:
        if len(user) > 2:
            _add(fields, user, base + 2, len(user) - 2, "User Data", _hx(user[2:]), "内层载荷")
        return fields
    ip = user[2:]
    if (ip[0] >> 4) != 4:
        _add(fields, user, base + 2, len(ip), "User Data", _hx(ip), "非标准 IPv4 头（如 IEEE 测试向量）")
        return fields
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    tot = int.from_bytes(ip[2:4], "big")
    _add(fields, user, base + 2, 1, "IP Ver/IHL", f"{ip[0]:#04x}", f"IPv4, IHL={ihl} B")
    _add(fields, user, base + 3, 1, "IP TOS", f"{ip[1]:#04x}", "")
    _add(fields, user, base + 4, 2, "IP Total Length", str(tot), "含 IP 头")
    _add(fields, user, base + 6, 2, "IP ID", f"{int.from_bytes(ip[4:6], 'big'):#06x}", "")
    _add(fields, user, base + 8, 2, "IP Flags/Frag", _hx(ip[6:8]), "")
    _add(fields, user, base + 10, 1, "TTL", str(ip[8]), "")
    _add(fields, user, base + 11, 1, "Protocol", str(proto), "1 = ICMP")
    _add(fields, user, base + 12, 2, "IP Checksum", _hx(ip[10:12]), "")
    _add(fields, user, base + 14, 4, "IP Src", _ip(ip[12:16]), "")
    _add(fields, user, base + 18, 4, "IP Dst", _ip(ip[16:20]), "")
    if proto != 1 or len(ip) < ihl + 8:
        rest = ip[ihl:]
        if rest:
            _add(fields, user, base + 2 + ihl, len(rest), "IP payload", _hx(rest), "")
        return fields
    icmp = ip[ihl:]
    o = base + 2 + ihl
    itype, icode = icmp[0], icmp[1]
    _add(fields, user, o, 1, "ICMP Type", str(itype), ICMP_TYPES.get(itype, "other"))
    _add(fields, user, o + 1, 1, "ICMP Code", str(icode), "")
    _add(fields, user, o + 2, 2, "ICMP Checksum", _hx(icmp[2:4]), "")
    _add(fields, user, o + 4, 2, "ICMP Identifier", str(int.from_bytes(icmp[4:6], "big")), "")
    _add(fields, user, o + 6, 2, "ICMP Sequence", str(int.from_bytes(icmp[6:8], "big")), "回显序号")
    if len(icmp) > 8:
        payload = icmp[8:]
        text = payload.decode("ascii", "replace")
        _add(fields, user, o + 8, len(payload), "ICMP Data", repr(text), f"{len(payload)} B payload")
    return fields


def dissect_mka(frame: bytes, keys: LabKeys) -> tuple[str, list[Field], dict]:
    parsed = parse_eapol_mka(frame, keys.ick, keys.kek)
    fields = ethernet_fields(frame, "802.1X EAPOL")
    eapol_off = 14
    _add(fields, frame, eapol_off, 1, "EAPOL Version", str(parsed["eapol_version"]), "3 = 802.1X-2010")
    _add(
        fields,
        frame,
        eapol_off + 1,
        1,
        "EAPOL Type",
        str(parsed["eapol_type"]),
        "5 = EAPOL-MKA（不是 6）",
    )
    _add(
        fields,
        frame,
        eapol_off + 2,
        2,
        "Packet Body Length",
        str(parsed["body_len"]),
        "含 ICV，不含以太网头",
    )
    mk_off = eapol_off + 4
    mk_body = parsed["mk_body"]
    for rel, total, code, name, obj in iter_mkpdu_sets(mk_body):
        abs_off = mk_off + rel
        chunk = mk_body[rel : rel + total]
        if code == 0:
            assert isinstance(obj, BasicParamSet)
            _add(fields, frame, abs_off, 1, "MKA Version", str(obj.version), "Basic 第 1 字节是版本不是 type")
            _add(
                fields,
                frame,
                abs_off + 1,
                1,
                "Key Server Priority",
                str(obj.ks_priority),
                "数值越小越优先",
            )
            _add(
                fields,
                frame,
                abs_off + 2,
                2,
                "KS/Desired/Cap + BodyLen",
                f"{int.from_bytes(chunk[2:4], 'big'):#06x}",
                f"KS={int(obj.key_server)} Desired={int(obj.macsec_desired)} "
                f"Cap={obj.macsec_capability}({CAP_NAMES[obj.macsec_capability]}) "
                f"body_len={_read_body_len(chunk, 2)}",
            )
            _add(fields, frame, abs_off + 4, 8, "SCI", obj.sci.hex(), "MAC ‖ Port ID")
            _add(fields, frame, abs_off + 12, 12, "Actor MI", obj.actor_mi.hex(), "12 字节成员标识")
            _add(fields, frame, abs_off + 24, 4, "Actor MN", str(obj.actor_mn), "本参与者报文序号")
            _add(
                fields,
                frame,
                abs_off + 28,
                4,
                "Algorithm Agility",
                obj.algo_agility.hex(),
                "00-80-C2-01 = 802.1X-2010 AES-CMAC",
            )
            ckn_off = abs_off + 32
            _add(
                fields,
                frame,
                ckn_off,
                len(obj.ckn),
                "CKN",
                obj.ckn.hex(),
                f"ASCII {obj.ckn.decode('ascii', 'replace')!r}，两端必须一致",
            )
            pad = total - (32 + len(obj.ckn))
            if pad:
                _add(fields, frame, ckn_off + len(obj.ckn), pad, "Basic padding", _hx(chunk[32 + len(obj.ckn) :]), "4 字节对齐")
            continue
        if code in (1, 2) and isinstance(obj, PeerList):
            _add(fields, frame, abs_off, 1, "Param type", str(code), name)
            _add(fields, frame, abs_off + 1, 1, "KS SSCI LSB", str(obj.key_server_ssci), "非 XPN 时为 0")
            _add(fields, frame, abs_off + 2, 2, "Body length", str(_read_body_len(chunk, 2)), "")
            p = abs_off + 4
            for i, peer in enumerate(obj.peers, 1):
                _add(fields, frame, p, 12, f"Peer {i} MI", peer.mi.hex(), "对端成员标识")
                _add(fields, frame, p + 12, 4, f"Peer {i} MN", str(peer.mn), "对端已确认的报文号")
                p += 16
            continue
        if code == 3 and isinstance(obj, SakUse):
            _add(fields, frame, abs_off, 1, "Param type", "3", "MACsec SAK Use")
            o2 = chunk[1]
            _add(
                fields,
                frame,
                abs_off + 1,
                1,
                "Latest/Old AN tx rx",
                f"{o2:#04x}",
                f"Latest AN={obj.latest_an} tx={int(obj.latest_tx)} rx={int(obj.latest_rx)}; "
                f"Old AN={obj.old_an} tx={int(obj.old_tx)} rx={int(obj.old_rx)}",
            )
            _add(
                fields,
                frame,
                abs_off + 2,
                2,
                "Plain/Delay + BodyLen",
                _hx(chunk[2:4]),
                f"plain_tx={int(obj.plain_tx)} plain_rx={int(obj.plain_rx)} delay_protect={int(obj.delay_protect)} "
                f"body={_read_body_len(chunk, 2)}",
            )
            if obj.macsec_supported:
                _add(fields, frame, abs_off + 4, 12, "Latest KS MI", obj.latest_server_mi.hex(), "KI 的 MI 部分")
                _add(fields, frame, abs_off + 16, 4, "Latest KN", str(obj.latest_kn), "KI 的 Key Number")
                _add(fields, frame, abs_off + 20, 4, "Latest lowest PN", str(obj.latest_lpn), "抗重放窗口下沿")
                _add(fields, frame, abs_off + 24, 12, "Old KS MI", obj.old_server_mi.hex(), "无旧钥时为 0")
                _add(fields, frame, abs_off + 36, 4, "Old KN", str(obj.old_kn), "")
                _add(fields, frame, abs_off + 40, 4, "Old lowest PN", str(obj.old_lpn), "")
            continue
        if code == 4 and isinstance(obj, DistributedSak):
            _add(fields, frame, abs_off, 1, "Param type", "4", "Distributed SAK")
            _add(
                fields,
                frame,
                abs_off + 1,
                1,
                "AN + Conf. offset",
                f"{chunk[1]:#04x}",
                f"AN={obj.an} offset_code={obj.confidentiality_offset} (0→0 字节)",
            )
            _add(fields, frame, abs_off + 2, 2, "Body length", str(_read_body_len(chunk, 2)), "28 = 默认 GCM-AES-128")
            _add(fields, frame, abs_off + 4, 4, "Key Number", str(obj.kn), "本把 SAK 的编号")
            wrap_off = abs_off + 8
            wrap_len = len(obj.wrapped_sak)
            note = "AES-KeyWrap(KEK, SAK)，24 B = 16 B SAK + 8 B wrap IV"
            if parsed.get("unwrapped_sak"):
                note += f"；解开 = {parsed['unwrapped_sak'].hex()}"
            _add(fields, frame, wrap_off, wrap_len, "AES-KW(SAK)", obj.wrapped_sak.hex(), note)
            continue
        _add(fields, frame, abs_off, total, name, _hx(chunk), "")

    icv_off = 14 + 4 + parsed["body_len"] - 16
    _add(
        fields,
        frame,
        icv_off,
        16,
        "MKA ICV",
        parsed["icv"].hex(),
        f"AES-CMAC(ICK)；校验 {'通过' if parsed['icv_ok'] else '失败/未验'}",
    )
    used = 14 + 4 + parsed["body_len"]
    if used < len(frame) and any(frame[used:]):
        _add(fields, frame, used, len(frame) - used, "Ethernet padding", _hx(frame[used:]), "补到 60 字节")
    elif used < len(frame):
        _add(fields, frame, used, len(frame) - used, "Ethernet padding", "00…", f"{len(frame) - used} 字节 0")

    title = (
        f"EAPOL-MKA  MN={parsed['basic'].actor_mn}  "
        f"{'Key Server' if parsed['basic'].key_server else '非 Key Server'}  "
        f"ICV={'OK' if parsed['icv_ok'] else 'FAIL'}"
    )
    return title, fields, parsed


def dissect_macsec(frame: bytes, sak: bytes, sci_a: bytes, sci_b: bytes) -> tuple[str, list[Field], dict, list[Field]]:
    parsed = None
    last_err = None
    for hint in (None, sci_a, sci_b):
        try:
            parsed = parse_frame(frame, sak, hint)
            if parsed["icv_ok"] is False:
                continue
            break
        except Exception as e:
            last_err = e
            parsed = None
    if parsed is None:
        raise ValueError(last_err)
    tag = parsed["tag"]
    fields = ethernet_fields(frame, "802.1AE MACsec")
    _add(fields, frame, 14, 1, "TCI/AN", f"{tag.tci:#04x}", tci_bits(tag.tci) + f"；模式 {tag.mode}")
    _add(fields, frame, 15, 1, "SL", str(tag.sl), "Secure Data < 48 时填长度，否则 0")
    _add(fields, frame, 16, 4, "PN", f"{tag.pn} ({tag.pn:#010x})", "抗重放；GCM IV 的低 32 bit")
    hdr = 20
    if tag.sc:
        _add(fields, frame, 20, 8, "SCI", parsed["sci"].hex(), "显式携带；IV 高 64 bit")
        hdr = 28
    else:
        fields.append(
            Field(
                20,
                0,
                "SCI (inferred)",
                parsed["sci"].hex(),
                "线上无 SCI；ES=1 时用 SA‖00-01 还原，仍参与 IV",
                parsed["sci"].hex(),
            )
        )
    sec_len = len(parsed["secure_data"])
    _add(
        fields,
        frame,
        hdr,
        sec_len,
        "Secure Data",
        _hx(parsed["secure_data"]),
        "密文" if tag.e else "明文 User Data（仅完整性）",
    )
    _add(
        fields,
        frame,
        hdr + sec_len,
        16,
        "MACsec ICV",
        parsed["icv"].hex(),
        f"GCM tag；校验 {'通过' if parsed['icv_ok'] else '失败'}",
    )
    used = hdr + sec_len + 16
    if used < len(frame):
        _add(fields, frame, used, len(frame) - used, "Ethernet padding", _hx(frame[used:]), "")

    inner: list[Field] = []
    if parsed["user_data"] is not None:
        inner = dissect_ipv4_user(parsed["user_data"])

    sci = parsed["sci"]
    iv = sci + tag.pn.to_bytes(4, "big")
    parsed["iv"] = iv
    parsed["aad_desc"] = (
        "DA‖SA‖SecTAG‖User Data（P 为空）" if not tag.e else "DA‖SA‖SecTAG（P = User Data）"
    )
    title = (
        f"MACsec  PN={tag.pn}  {tag.mode}  "
        f"{'SC=1' if tag.sc else 'ES=1 无 SCI'}  ICV={'OK' if parsed['icv_ok'] else 'FAIL'}"
    )
    return title, fields, parsed, inner


def one_line(frame: bytes, keys: LabKeys, sci_a: bytes, sci_b: bytes) -> str:
    et = int.from_bytes(frame[12:14], "big")
    if et == ETHERTYPE_EAPOL:
        p = parse_eapol_mka(frame, keys.ick, keys.kek)
        sets = ", ".join(s["type"] for s in p["param_sets"]) or "仅 Basic"
        role = "KS" if p["basic"].key_server else "peer"
        return f"MKA MN={p['basic'].actor_mn} {role}: {sets}"
    if et == ETHERTYPE_MACSEC:
        _, _, p, inner = dissect_macsec(frame, keys.sak, sci_a, sci_b)
        tag = p["tag"]
        seq = ""
        for f in inner:
            if f.name == "ICMP Sequence":
                seq = f" ICMP seq={f.value}"
                break
        return f"MACsec PN={tag.pn} {tag.mode}{seq}"
    return f"EtherType {et:#06x}"
