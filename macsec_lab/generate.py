"""Write reference PCAPs and keys.json into captures/."""

from __future__ import annotations

import json
from pathlib import Path

from .keys import LabKeys
from .pcap import PcapPacket, pad_ethernet, write_pcap
from .scenario import (
    ieee_encrypt_frame,
    ieee_integrity_frame,
    macsec_lab_data,
    mka_handshake,
)


def _packets(frames: list[tuple[str, bytes]], t0: int = 1_700_000_000) -> list[PcapPacket]:
    out = []
    for i, (_, raw) in enumerate(frames):
        out.append(PcapPacket(t0 + i, 0, pad_ethernet(raw)))
    return out


def generate(out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    keys = LabKeys.default()
    (out_dir / "keys.json").write_text(json.dumps(keys.as_dict(), indent=2) + "\n")

    mka = mka_handshake(keys)
    enc = macsec_lab_data(keys, encrypt=True)
    integ = macsec_lab_data(keys, encrypt=False)
    ieee_i = [("IEEE GCM-AES-128 integrity-only test vector", ieee_integrity_frame())]
    ieee_e = [("IEEE GCM-AES-128 confidentiality test vector", ieee_encrypt_frame())]
    full = mka + enc

    mapping = {
        "mka-handshake.pcap": mka,
        "macsec-lab-encrypted.pcap": enc,
        "macsec-lab-integrity-only.pcap": integ,
        "macsec-ieee-gcm-aes-128-integrity.pcap": ieee_i,
        "macsec-ieee-gcm-aes-128-encrypt.pcap": ieee_e,
        "session-full.pcap": full,
    }
    written: dict[str, Path] = {}
    for name, frames in mapping.items():
        path = out_dir / name
        write_pcap(path, _packets(frames))
        written[name] = path
    (out_dir / "frame-index.json").write_text(
        json.dumps(
            {name: [c for c, _ in frames] for name, frames in mapping.items()},
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )
    return written
