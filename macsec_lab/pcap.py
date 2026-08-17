"""Minimal PCAP (DLT_EN10MB) reader/writer. Frames are stored without FCS."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

PCAP_MAGIC = 0xA1B2C3D4
DLT_EN10MB = 1


@dataclass
class PcapPacket:
    ts_sec: int
    ts_usec: int
    data: bytes


def write_pcap(path: Path, packets: list[PcapPacket]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        f.write(struct.pack("<IHHIIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, DLT_EN10MB))
        for p in packets:
            f.write(struct.pack("<IIII", p.ts_sec, p.ts_usec, len(p.data), len(p.data)))
            f.write(p.data)


def read_pcap(path: Path) -> list[PcapPacket]:
    data = path.read_bytes()
    magic, major, minor, _, _, _, network = struct.unpack_from("<IHHIIII", data, 0)
    if magic != PCAP_MAGIC:
        raise ValueError(f"unsupported pcap magic {magic:#x}")
    if network != DLT_EN10MB:
        raise ValueError(f"expected Ethernet pcap, got DLT {network}")
    off = 24
    packets: list[PcapPacket] = []
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, orig = struct.unpack_from("<IIII", data, off)
        off += 16
        packets.append(PcapPacket(ts_sec, ts_usec, data[off : off + incl]))
        off += incl
    return packets


def pad_ethernet(frame: bytes, min_len: int = 60) -> bytes:
    """Pad to Ethernet minimum (60 octets without FCS)."""
    if len(frame) >= min_len:
        return frame
    return frame + bytes(min_len - len(frame))
