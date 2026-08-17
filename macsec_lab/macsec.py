"""IEEE 802.1AE SecTAG encode/decode and GCM-AES-128 protect/validate."""

from __future__ import annotations

from dataclasses import dataclass

from .crypto import gcm_protect, gcm_validate
from .keys import ETHERTYPE_MACSEC

# TCI bit masks (IEEE 802.1AE Figure 9-1, bit 8 = MSB)
TCI_V = 0x80
TCI_ES = 0x40
TCI_SC = 0x20
TCI_SCB = 0x10
TCI_E = 0x08
TCI_C = 0x04
TCI_AN = 0x03


@dataclass
class SecTAG:
    tci: int
    sl: int
    pn: int
    sci: bytes | None  # 8 octets when SC=1, else None

    @property
    def v(self) -> int:
        return (self.tci & TCI_V) >> 7

    @property
    def es(self) -> bool:
        return bool(self.tci & TCI_ES)

    @property
    def sc(self) -> bool:
        return bool(self.tci & TCI_SC)

    @property
    def scb(self) -> bool:
        return bool(self.tci & TCI_SCB)

    @property
    def e(self) -> bool:
        return bool(self.tci & TCI_E)

    @property
    def c(self) -> bool:
        return bool(self.tci & TCI_C)

    @property
    def an(self) -> int:
        return self.tci & TCI_AN

    @property
    def mode(self) -> str:
        if self.e and self.c:
            return "confidentiality+integrity"
        if (not self.e) and (not self.c):
            return "integrity-only"
        if (not self.e) and self.c:
            return "integrity-only (changed)"
        return "illegal (E=1,C=0)"

    def pack(self) -> bytes:
        sl_octet = self.sl & 0x3F
        body = bytes([self.tci & 0xFF, sl_octet]) + self.pn.to_bytes(4, "big")
        if self.sc:
            if self.sci is None or len(self.sci) != 8:
                raise ValueError("SC=1 requires 8-octet SCI")
            body += self.sci
        return body

    def pack_with_ethertype(self) -> bytes:
        return ETHERTYPE_MACSEC.to_bytes(2, "big") + self.pack()

    @classmethod
    def unpack(cls, buf: bytes) -> tuple["SecTAG", int]:
        if len(buf) < 6:
            raise ValueError("SecTAG too short")
        tci, sl = buf[0], buf[1] & 0x3F
        pn = int.from_bytes(buf[2:6], "big")
        has_sci = bool(tci & TCI_SC)
        if has_sci:
            if len(buf) < 14:
                raise ValueError("SecTAG SC=1 but SCI missing")
            return cls(tci, sl, pn, buf[6:14]), 14
        return cls(tci, sl, pn, None), 6

    @classmethod
    def build(
        cls,
        *,
        pn: int,
        an: int = 0,
        encrypt: bool = True,
        sci: bytes | None = None,
        es: bool = False,
        sl: int = 0,
        scb: bool = False,
    ) -> "SecTAG":
        tci = an & TCI_AN
        if es:
            tci |= TCI_ES
        if sci is not None:
            tci |= TCI_SC
        if scb:
            tci |= TCI_SCB
        if encrypt:
            tci |= TCI_E | TCI_C
        return cls(tci=tci, sl=sl, pn=pn, sci=sci)


def short_length(user_data_len: int) -> int:
    """SL is the Secure Data length when that length is < 48, else 0."""
    return user_data_len if user_data_len < 48 else 0


def infer_sci(sa: bytes, tag: SecTAG, fallback: bytes | None = None) -> bytes:
    if tag.sci is not None:
        return tag.sci
    if fallback is not None:
        return fallback
    if tag.es and not tag.scb:
        return sa + b"\x00\x01"
    if tag.scb and not tag.es:
        return sa + b"\x00\x00"
    raise ValueError("SCI not present and cannot be inferred (need ES or explicit SCI)")


def protect_frame(
    da: bytes,
    sa: bytes,
    user_data: bytes,
    sak: bytes,
    tag: SecTAG,
    sci_for_iv: bytes,
) -> bytes:
    """Build a complete Ethernet MACsec frame (no FCS).

    user_data is the original EtherType + payload (the MSDU after DA/SA).
    """
    tag.sl = short_length(len(user_data))
    sectag = tag.pack_with_ethertype()
    iv = sci_for_iv + tag.pn.to_bytes(4, "big")
    if tag.e:
        aad = da + sa + sectag
        ciphertext, icv = gcm_protect(sak, iv, aad, user_data)
        secure = ciphertext
    else:
        aad = da + sa + sectag + user_data
        _, icv = gcm_protect(sak, iv, aad, b"")
        secure = user_data
    return da + sa + sectag + secure + icv


def parse_frame(frame: bytes, sak: bytes | None = None, sci_hint: bytes | None = None) -> dict:
    if len(frame) < 14 + 6 + 16:
        raise ValueError("frame too short for MACsec")
    da, sa = frame[0:6], frame[6:12]
    etype = int.from_bytes(frame[12:14], "big")
    if etype != ETHERTYPE_MACSEC:
        raise ValueError(f"not MACsec EtherType: {etype:#06x}")
    tag, tag_len = SecTAG.unpack(frame[14:])
    hdr_len = 14 + tag_len
    if len(frame) < hdr_len + 16:
        raise ValueError("truncated ICV")
    icv = frame[-16:]
    secure = frame[hdr_len:-16]
    sci = infer_sci(sa, tag, sci_hint)
    result = {
        "da": da,
        "sa": sa,
        "ethertype": etype,
        "tag": tag,
        "sci": sci,
        "secure_data": secure,
        "icv": icv,
        "user_data": None,
        "icv_ok": None,
    }
    if sak is None:
        if not tag.e:
            result["user_data"] = secure
        return result
    iv = sci + tag.pn.to_bytes(4, "big")
    sectag = tag.pack_with_ethertype()
    try:
        if tag.e:
            aad = da + sa + sectag
            result["user_data"] = gcm_validate(sak, iv, aad, secure, icv)
        else:
            aad = da + sa + sectag + secure
            gcm_validate(sak, iv, aad, b"", icv)
            result["user_data"] = secure
        result["icv_ok"] = True
    except Exception:
        result["icv_ok"] = False
    return result
