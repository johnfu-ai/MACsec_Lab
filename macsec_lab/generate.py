"""Write reference PCAPs and keys.json into captures/."""

from __future__ import annotations

import json
from pathlib import Path

from .keys import LabKeys
from .pcap import PcapPacket, pad_ethernet, write_pcap
from .scenario import (
    ieee_encrypt_frame,
    ieee_integrity_frame,
    ieee256_encrypt_frame,
    ieee256_integrity_frame,
    macsec_lab_data,
    mka_after_eap,
    mka_co30,
    mka_handshake,
    mka_multi_peer,
    mka_rekey,
    mka_xpn,
)


def _packets(frames: list[tuple[str, bytes]], t0: int = 1_700_000_000) -> list[PcapPacket]:
    out = []
    for i, (_, raw) in enumerate(frames):
        out.append(PcapPacket(t0 + i, 0, pad_ethernet(raw)))
    return out


def generate(out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    keys = LabKeys.default()
    eap_keys = LabKeys.eap_default()
    blob = keys.as_dict()
    blob["eap"] = eap_keys.as_dict()
    (out_dir / "keys.json").write_text(json.dumps(blob, indent=2) + "\n")

    mka = mka_handshake(keys)
    eap_mka = mka_after_eap(eap_keys)
    rekey = mka_rekey(keys)
    co30 = mka_co30(keys)
    xpn = mka_xpn(keys)
    multi = mka_multi_peer(keys)
    enc = macsec_lab_data(keys, encrypt=True)
    integ = macsec_lab_data(keys, encrypt=False)
    ieee_i = [("IEEE GCM-AES-128 integrity-only test vector", ieee_integrity_frame())]
    ieee_e = [("IEEE GCM-AES-128 confidentiality test vector", ieee_encrypt_frame())]
    ieee_i256 = [("IEEE GCM-AES-256 integrity-only test vector (Randall 2.1.2)", ieee256_integrity_frame())]
    ieee_e256 = [("IEEE GCM-AES-256 confidentiality test vector (Randall 2.2.2)", ieee256_encrypt_frame())]
    full = mka + enc

    mapping = {
        "mka-handshake.pcap": mka,
        "mka-after-eap.pcap": eap_mka,
        "mka-rekey.pcap": rekey,
        "mka-co30.pcap": co30,
        "mka-xpn.pcap": xpn,
        "mka-multi-peer.pcap": multi,
        "macsec-lab-encrypted.pcap": enc,
        "macsec-lab-integrity-only.pcap": integ,
        "macsec-ieee-gcm-aes-128-integrity.pcap": ieee_i,
        "macsec-ieee-gcm-aes-128-encrypt.pcap": ieee_e,
        "macsec-ieee-gcm-aes-256-integrity.pcap": ieee_i256,
        "macsec-ieee-gcm-aes-256-encrypt.pcap": ieee_e256,
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
