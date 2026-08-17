"""Build IPv4/ICMP payloads used as MACsec User Data."""

from __future__ import annotations

from .keys import ETHERTYPE_IPV4


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4_icmp_echo(src: str, dst: str, ident: int, seq: int, payload: bytes = b"macsec-lab") -> bytes:
    src_b = bytes(int(x) for x in src.split("."))
    dst_b = bytes(int(x) for x in dst.split("."))
    icmp = bytes([8, 0, 0, 0]) + ident.to_bytes(2, "big") + seq.to_bytes(2, "big") + payload
    csum = _checksum(icmp)
    icmp = icmp[:2] + csum.to_bytes(2, "big") + icmp[4:]

    ihl = 20
    total = ihl + len(icmp)
    ip = bytearray(20)
    ip[0] = 0x45
    ip[1] = 0
    ip[2:4] = total.to_bytes(2, "big")
    ip[4:6] = ident.to_bytes(2, "big")
    ip[6:8] = b"\x00\x00"
    ip[8] = 64
    ip[9] = 1  # ICMP
    ip[12:16] = src_b
    ip[16:20] = dst_b
    ip[10:12] = _checksum(bytes(ip)).to_bytes(2, "big")
    return ETHERTYPE_IPV4.to_bytes(2, "big") + bytes(ip) + icmp
