"""IEEE 802.1X-2020 MKPDU (EAPOL-MKA) encode / decode."""

from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import aes_cmac, unwrap_sak, wrap_sak
from .keys import (
    EAPOL_TYPE_MKA,
    EAPOL_VERSION,
    ETHERTYPE_EAPOL,
    MKA_ALGO_AGILITY,
    PAE_GROUP_ADDR,
)

# Table 11-7 parameter set types (Basic uses version in octet 1 instead of type)
PS_LIVE_PEER = 1
PS_POTENTIAL_PEER = 2
PS_SAK_USE = 3
PS_DISTRIBUTED_SAK = 4
PS_ICV_INDICATOR = 255

MKA_ICV_LEN = 16
MI_LEN = 12


def _body_len_bytes(body_len: int, extra_hi_nibble: int = 0) -> bytes:
    """12-bit body length occupying bits 4-1 of octet 3 and octet 4.

    extra_hi_nibble is the high nibble of the first of those two bytes
    (flags already placed in bits 8-5 of octet 3).
    """
    if not 0 <= body_len <= 0x0FFF:
        raise ValueError("parameter set body length out of range")
    b0 = (extra_hi_nibble & 0xF0) | ((body_len >> 8) & 0x0F)
    b1 = body_len & 0xFF
    return bytes([b0, b1])


def _read_body_len(octets: bytes, offset: int) -> int:
    return int.from_bytes(octets[offset : offset + 2], "big") & 0x0FFF


def _pad4(n: int) -> int:
    return (4 - (n % 4)) % 4


@dataclass
class PeerTuple:
    mi: bytes
    mn: int

    def pack(self) -> bytes:
        if len(self.mi) != MI_LEN:
            raise ValueError("MI must be 12 octets")
        return self.mi + self.mn.to_bytes(4, "big")

    @classmethod
    def unpack(cls, buf: bytes) -> "PeerTuple":
        return cls(buf[:12], int.from_bytes(buf[12:16], "big"))


@dataclass
class BasicParamSet:
    version: int
    ks_priority: int
    key_server: bool
    macsec_desired: bool
    macsec_capability: int  # 0..3
    sci: bytes
    actor_mi: bytes
    actor_mn: int
    algo_agility: bytes = MKA_ALGO_AGILITY
    ckn: bytes = b""

    def pack(self) -> bytes:
        flags = 0
        if self.key_server:
            flags |= 0x80
        if self.macsec_desired:
            flags |= 0x40
        flags |= (self.macsec_capability & 0x03) << 4
        body = self.sci + self.actor_mi + self.actor_mn.to_bytes(4, "big") + self.algo_agility + self.ckn
        hdr = bytes([self.version, self.ks_priority]) + _body_len_bytes(len(body), flags)
        raw = hdr + body
        return raw + bytes(_pad4(len(raw)))

    @classmethod
    def unpack(cls, buf: bytes) -> tuple["BasicParamSet", int]:
        version, prio = buf[0], buf[1]
        flags = buf[2]
        body_len = _read_body_len(buf, 2)
        total = 4 + body_len
        total += _pad4(total)
        body = buf[4 : 4 + body_len]
        sci, mi = body[0:8], body[8:20]
        mn = int.from_bytes(body[20:24], "big")
        algo = body[24:28]
        ckn = body[28:]
        return (
            cls(
                version=version,
                ks_priority=prio,
                key_server=bool(flags & 0x80),
                macsec_desired=bool(flags & 0x40),
                macsec_capability=(flags >> 4) & 0x03,
                sci=sci,
                actor_mi=mi,
                actor_mn=mn,
                algo_agility=algo,
                ckn=ckn,
            ),
            total,
        )


@dataclass
class PeerList:
    ptype: int
    peers: list[PeerTuple]
    key_server_ssci: int = 0

    def pack(self) -> bytes:
        body = b"".join(p.pack() for p in self.peers)
        hdr = bytes([self.ptype, self.key_server_ssci & 0xFF]) + _body_len_bytes(len(body))
        raw = hdr + body
        return raw + bytes(_pad4(len(raw)))

    @classmethod
    def unpack(cls, buf: bytes) -> tuple["PeerList", int]:
        ptype = buf[0]
        ssci = buf[1]
        body_len = _read_body_len(buf, 2)
        total = 4 + body_len + _pad4(4 + body_len)
        body = buf[4 : 4 + body_len]
        peers = [PeerTuple.unpack(body[i : i + 16]) for i in range(0, len(body), 16) if i + 16 <= len(body)]
        return cls(ptype, peers, ssci), total


@dataclass
class SakUse:
    latest_an: int
    latest_tx: bool
    latest_rx: bool
    old_an: int = 0
    old_tx: bool = False
    old_rx: bool = False
    plain_tx: bool = False
    plain_rx: bool = False
    delay_protect: bool = True
    latest_server_mi: bytes = b"\x00" * 12
    latest_kn: int = 0
    latest_lpn: int = 1
    old_server_mi: bytes = b"\x00" * 12
    old_kn: int = 0
    old_lpn: int = 1
    macsec_supported: bool = True

    def pack(self) -> bytes:
        o2 = ((self.latest_an & 3) << 6)
        if self.latest_tx:
            o2 |= 0x20
        if self.latest_rx:
            o2 |= 0x10
        o2 |= (self.old_an & 3) << 2
        if self.old_tx:
            o2 |= 0x02
        if self.old_rx:
            o2 |= 0x01
        o3_hi = 0
        if self.plain_tx:
            o3_hi |= 0x80
        if self.plain_rx:
            o3_hi |= 0x40
        if self.delay_protect:
            o3_hi |= 0x10
        if self.macsec_supported:
            body = (
                self.latest_server_mi
                + self.latest_kn.to_bytes(4, "big")
                + self.latest_lpn.to_bytes(4, "big")
                + self.old_server_mi
                + self.old_kn.to_bytes(4, "big")
                + self.old_lpn.to_bytes(4, "big")
            )
        else:
            body = b""
        hdr = bytes([PS_SAK_USE, o2]) + _body_len_bytes(len(body), o3_hi)
        raw = hdr + body
        return raw + bytes(_pad4(len(raw)))

    @classmethod
    def unpack(cls, buf: bytes) -> tuple["SakUse", int]:
        o2 = buf[1]
        o3 = buf[2]
        body_len = _read_body_len(buf, 2)
        total = 4 + body_len + _pad4(4 + body_len)
        body = buf[4 : 4 + body_len]
        obj = cls(
            latest_an=(o2 >> 6) & 3,
            latest_tx=bool(o2 & 0x20),
            latest_rx=bool(o2 & 0x10),
            old_an=(o2 >> 2) & 3,
            old_tx=bool(o2 & 0x02),
            old_rx=bool(o2 & 0x01),
            plain_tx=bool(o3 & 0x80),
            plain_rx=bool(o3 & 0x40),
            delay_protect=bool(o3 & 0x10),
            macsec_supported=body_len == 40,
        )
        if body_len == 40:
            obj.latest_server_mi = body[0:12]
            obj.latest_kn = int.from_bytes(body[12:16], "big")
            obj.latest_lpn = int.from_bytes(body[16:20], "big")
            obj.old_server_mi = body[20:32]
            obj.old_kn = int.from_bytes(body[32:36], "big")
            obj.old_lpn = int.from_bytes(body[36:40], "big")
        return obj, total


@dataclass
class DistributedSak:
    an: int
    confidentiality_offset: int  # 0=0, 1=30, 2=50
    kn: int
    wrapped_sak: bytes  # 24 octets for AES-128
    cipher_suite: bytes | None = None

    def pack(self) -> bytes:
        o2 = ((self.an & 3) << 6) | ((self.confidentiality_offset & 3) << 4)
        if self.cipher_suite:
            body = self.kn.to_bytes(4, "big") + self.cipher_suite + self.wrapped_sak
        else:
            body = self.kn.to_bytes(4, "big") + self.wrapped_sak
        hdr = bytes([PS_DISTRIBUTED_SAK, o2]) + _body_len_bytes(len(body))
        raw = hdr + body
        return raw + bytes(_pad4(len(raw)))

    @classmethod
    def unpack(cls, buf: bytes) -> tuple["DistributedSak", int]:
        o2 = buf[1]
        body_len = _read_body_len(buf, 2)
        total = 4 + body_len + _pad4(4 + body_len)
        body = buf[4 : 4 + body_len]
        an = (o2 >> 6) & 3
        offset = (o2 >> 4) & 3
        if body_len == 0:
            return cls(an, offset, 0, b""), total
        kn = int.from_bytes(body[0:4], "big")
        rest = body[4:]
        if body_len == 28:
            return cls(an, offset, kn, rest), total
        if len(rest) >= 8 + 24:
            return cls(an, offset, kn, rest[8:], rest[:8]), total
        return cls(an, offset, kn, rest), total


@dataclass
class MkPdu:
    basic: BasicParamSet
    param_sets: list[object] = field(default_factory=list)
    icv: bytes = b""

    def pack_body(self) -> bytes:
        parts = [self.basic.pack()]
        for ps in self.param_sets:
            parts.append(ps.pack())  # type: ignore[union-attr]
        return b"".join(parts)

    def pack_eapol(self, icv: bytes) -> bytes:
        body = self.pack_body() + icv
        return bytes([EAPOL_VERSION, EAPOL_TYPE_MKA]) + len(body).to_bytes(2, "big") + body


def mka_icv_input(da: bytes, sa: bytes, eapol_without_icv: bytes) -> bytes:
    """IEEE 802.1X 9.4.1: M = DA + SA + (MSDU – ICV)."""
    return da + sa + ETHERTYPE_EAPOL.to_bytes(2, "big") + eapol_without_icv


def seal_mkpdu(da: bytes, sa: bytes, pdu: MkPdu, ick: bytes) -> bytes:
    eapol_wo = pdu.pack_eapol(b"")
    # pack_eapol with empty ICV still puts body length without ICV — fix length.
    body = pdu.pack_body()
    eapol_wo = bytes([EAPOL_VERSION, EAPOL_TYPE_MKA]) + (len(body) + MKA_ICV_LEN).to_bytes(2, "big") + body
    icv = aes_cmac(ick, mka_icv_input(da, sa, eapol_wo))
    pdu.icv = icv
    return da + sa + ETHERTYPE_EAPOL.to_bytes(2, "big") + eapol_wo + icv


def parse_eapol_mka(frame: bytes, ick: bytes | None = None, kek: bytes | None = None) -> dict:
    da, sa = frame[0:6], frame[6:12]
    etype = int.from_bytes(frame[12:14], "big")
    if etype != ETHERTYPE_EAPOL:
        raise ValueError(f"not EAPOL: {etype:#06x}")
    eapol = frame[14:]
    # Strip Ethernet padding after the EAPOL Packet Body.
    ver, ptype = eapol[0], eapol[1]
    body_len = int.from_bytes(eapol[2:4], "big")
    eapol = eapol[: 4 + body_len]
    if ptype != EAPOL_TYPE_MKA:
        raise ValueError(f"EAPOL type {ptype} is not MKA (5)")
    if body_len < 16:
        raise ValueError("MKPDU body shorter than ICV")
    icv = eapol[-16:]
    mk_body = eapol[4:-16]
    eapol_wo = eapol[:-16]
    icv_ok = None
    if ick is not None:
        icv_ok = aes_cmac(ick, mka_icv_input(da, sa, eapol_wo)) == icv

    basic, n = BasicParamSet.unpack(mk_body)
    off = n
    sets: list[dict] = []
    unwrapped_sak = None
    while off + 4 <= len(mk_body):
        ptype_i = mk_body[off]
        blen = _read_body_len(mk_body, off + 2)
        total = 4 + blen + _pad4(4 + blen)
        chunk = mk_body[off : off + total]
        if ptype_i == PS_LIVE_PEER:
            pl, _ = PeerList.unpack(chunk)
            sets.append({"type": "Live Peer List", "code": 1, "peers": pl.peers, "ssci": pl.key_server_ssci})
        elif ptype_i == PS_POTENTIAL_PEER:
            pl, _ = PeerList.unpack(chunk)
            sets.append({"type": "Potential Peer List", "code": 2, "peers": pl.peers, "ssci": pl.key_server_ssci})
        elif ptype_i == PS_SAK_USE:
            su, _ = SakUse.unpack(chunk)
            sets.append({"type": "MACsec SAK Use", "code": 3, "body": su})
        elif ptype_i == PS_DISTRIBUTED_SAK:
            ds, _ = DistributedSak.unpack(chunk)
            rec = {"type": "Distributed SAK", "code": 4, "body": ds}
            if kek is not None and ds.wrapped_sak:
                rec["unwrapped_sak"] = unwrap_sak(kek, ds.wrapped_sak)
                unwrapped_sak = rec["unwrapped_sak"]
            sets.append(rec)
        elif ptype_i == PS_ICV_INDICATOR:
            sets.append({"type": "ICV Indicator", "code": 255, "icv_len": blen})
            break
        else:
            sets.append({"type": f"Unknown({ptype_i})", "code": ptype_i, "raw": chunk})
        off += total

    return {
        "da": da,
        "sa": sa,
        "eapol_version": ver,
        "eapol_type": ptype,
        "body_len": body_len,
        "basic": basic,
        "param_sets": sets,
        "icv": icv,
        "icv_ok": icv_ok,
        "unwrapped_sak": unwrapped_sak,
        "mk_body": mk_body,
        "eapol": eapol,
        "wire_len": 14 + 4 + body_len,
    }


def iter_mkpdu_sets(mk_body: bytes):
    """Yield (offset, total_len, type_code, name, object) covering mk_body."""
    basic, n = BasicParamSet.unpack(mk_body)
    yield 0, n, 0, "Basic Parameter Set", basic
    off = n
    while off + 4 <= len(mk_body):
        code = mk_body[off]
        blen = _read_body_len(mk_body, off + 2)
        total = 4 + blen + _pad4(4 + blen)
        chunk = mk_body[off : off + total]
        if code == PS_LIVE_PEER:
            obj, _ = PeerList.unpack(chunk)
            name = "Live Peer List"
        elif code == PS_POTENTIAL_PEER:
            obj, _ = PeerList.unpack(chunk)
            name = "Potential Peer List"
        elif code == PS_SAK_USE:
            obj, _ = SakUse.unpack(chunk)
            name = "MACsec SAK Use"
        elif code == PS_DISTRIBUTED_SAK:
            obj, _ = DistributedSak.unpack(chunk)
            name = "Distributed SAK"
        elif code == PS_ICV_INDICATOR:
            yield off, total, code, "ICV Indicator", None
            break
        else:
            yield off, total, code, f"Unknown({code})", chunk
            off += total
            continue
        yield off, total, code, name, obj
        off += total


def build_mkpdu_frame(
    *,
    sa: bytes,
    ick: bytes,
    basic: BasicParamSet,
    param_sets: list[object] | None = None,
    da: bytes = PAE_GROUP_ADDR,
) -> bytes:
    return seal_mkpdu(da, sa, MkPdu(basic, param_sets or []), ick)
