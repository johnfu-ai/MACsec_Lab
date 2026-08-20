"""Reference frame sequences for the learning captures."""

from __future__ import annotations

from dataclasses import replace

from .crypto import wrap_sak
from .keys import (
    EAP_CODE_SUCCESS,
    EAPOL_TYPE_EAP,
    EAPOL_VERSION,
    ETHERTYPE_EAPOL,
    IEEE_DA,
    IEEE_ENC_USER,
    IEEE_INT_USER,
    IEEE_PN,
    IEEE_SA,
    IEEE_SCI,
    IEEE_GCM_KEY_128,
    IEEE_GCM_KEY_256,
    LabKeys,
)
from .l3 import ipv4_icmp_echo
from .macsec import SecTAG, protect_frame
from .mka import (
    BasicParamSet,
    DistributedSak,
    PeerList,
    PeerTuple,
    SakUse,
    build_mkpdu_frame,
)


def _basic(peer, keys: LabKeys, mn: int, key_server: bool) -> BasicParamSet:
    """Basic Parameter Set shared by every MKPDU story."""
    return BasicParamSet(
        version=2,
        ks_priority=peer.ks_priority,
        key_server=key_server,
        macsec_desired=True,
        macsec_capability=3,
        sci=peer.sci,
        actor_mi=peer.mi,
        actor_mn=mn,
        ckn=keys.ckn,
    )


def eap_success_frame(authenticator_mac: bytes, supplicant_mac: bytes, identifier: int = 2) -> bytes:
    """EAPOL-EAP Success (type 0, EAP code 3). Unicast to the supplicant."""
    eap = bytes([EAP_CODE_SUCCESS, identifier & 0xFF]) + (4).to_bytes(2, "big")
    eapol = bytes([EAPOL_VERSION, EAPOL_TYPE_EAP]) + len(eap).to_bytes(2, "big") + eap
    return (
        supplicant_mac
        + authenticator_mac
        + ETHERTYPE_EAPOL.to_bytes(2, "big")
        + eapol
    )


def mka_handshake(keys: LabKeys, a_label: str = "A", b_label: str = "B") -> list[tuple[str, bytes]]:
    """Point-to-point MKA: elect Key Server, distribute SAK, both use it.

    Same MKPDU parameter sets for PSK CAK and EAP-derived CAK. Callers differ
    by LabKeys (CAK source, KS priority) and the optional EAP-Success prefix.
    """
    a, b = keys.a, keys.b
    wrapped = wrap_sak(keys.kek, keys.sak)
    frames: list[tuple[str, bytes]] = []

    frames.append(
        (
            f"{a_label} MN=1 hello (claim Key Server, no peers yet)",
            build_mkpdu_frame(sa=a.mac, ick=keys.ick, basic=_basic(a, keys, 1, True)),
        )
    )
    frames.append(
        (
            f"{b_label} MN=1 hello (saw {a_label}; Potential Peer List; not Key Server)",
            build_mkpdu_frame(
                sa=b.mac,
                ick=keys.ick,
                basic=_basic(b, keys, 1, False),
                param_sets=[PeerList(2, [PeerTuple(a.mi, 1)])],
            ),
        )
    )
    frames.append(
        (
            f"{a_label} MN=2 Key Server: Live Peer List + Distributed SAK + SAK Use (tx)",
            build_mkpdu_frame(
                sa=a.mac,
                ick=keys.ick,
                basic=_basic(a, keys, 2, True),
                param_sets=[
                    DistributedSak(an=keys.an, confidentiality_offset=0, kn=keys.kn, wrapped_sak=wrapped),
                    SakUse(
                        latest_an=keys.an,
                        latest_tx=True,
                        latest_rx=False,
                        delay_protect=True,
                        latest_server_mi=a.mi,
                        latest_kn=keys.kn,
                        latest_lpn=1,
                    ),
                    PeerList(1, [PeerTuple(b.mi, 1)]),
                ],
            ),
        )
    )
    frames.append(
        (
            f"{b_label} MN=2: Live Peer List + SAK Use (tx+rx) after installing SAK",
            build_mkpdu_frame(
                sa=b.mac,
                ick=keys.ick,
                basic=_basic(b, keys, 2, False),
                param_sets=[
                    SakUse(
                        latest_an=keys.an,
                        latest_tx=True,
                        latest_rx=True,
                        delay_protect=True,
                        latest_server_mi=a.mi,
                        latest_kn=keys.kn,
                        latest_lpn=1,
                    ),
                    PeerList(1, [PeerTuple(a.mi, 2)]),
                ],
            ),
        )
    )
    frames.append(
        (
            f"{a_label} MN=3: both sides using SAK (tx+rx), session up",
            build_mkpdu_frame(
                sa=a.mac,
                ick=keys.ick,
                basic=_basic(a, keys, 3, True),
                param_sets=[
                    SakUse(
                        latest_an=keys.an,
                        latest_tx=True,
                        latest_rx=True,
                        delay_protect=True,
                        latest_server_mi=a.mi,
                        latest_kn=keys.kn,
                        latest_lpn=1,
                    ),
                    PeerList(1, [PeerTuple(b.mi, 2)]),
                ],
            ),
        )
    )
    frames.append(
        (
            f"{b_label} MN=3 keepalive",
            build_mkpdu_frame(
                sa=b.mac,
                ick=keys.ick,
                basic=_basic(b, keys, 3, False),
                param_sets=[
                    SakUse(
                        latest_an=keys.an,
                        latest_tx=True,
                        latest_rx=True,
                        delay_protect=True,
                        latest_server_mi=a.mi,
                        latest_kn=keys.kn,
                        latest_lpn=1,
                    ),
                    PeerList(1, [PeerTuple(a.mi, 3)]),
                ],
            ),
        )
    )
    return frames


def mka_after_eap(keys: LabKeys) -> list[tuple[str, bytes]]:
    """EAP-Success then MKA. CAK/CKN already derived from MSK (off-wire)."""
    success = eap_success_frame(keys.a.mac, keys.b.mac)
    mka = mka_handshake(keys, a_label="Authenticator", b_label="Supplicant")
    return [
        ("EAP-Success (Authenticator → Supplicant; MSK already on both sides)", success),
        *mka,
    ]


def _sak_use(
    latest: tuple[int, bool, bool],
    ks_mi: bytes,
    kn: int,
    lpn: int,
    old: tuple[int, bool, bool] = (0, False, False),
    old_kn: int = 0,
    old_lpn: int = 1,
) -> SakUse:
    return SakUse(
        latest_an=latest[0],
        latest_tx=latest[1],
        latest_rx=latest[2],
        delay_protect=True,
        latest_server_mi=ks_mi,
        latest_kn=kn,
        latest_lpn=lpn,
        old_an=old[0],
        old_tx=old[1],
        old_rx=old[2],
        old_server_mi=ks_mi if old_kn else b"\x00" * 12,
        old_kn=old_kn,
        old_lpn=old_lpn,
    )


def mka_rekey(keys: LabKeys) -> list[tuple[str, bytes]]:
    """SAK rekey story: run on SAK#1 (AN=0), roll to SAK#2 (AN=1), retire SAK#1.

    Continues the PSK story of mka_handshake (MN 1-3 already used). The Key
    Server distributes a second SAK before PN exhaustion; both sides keep the
    old SA receive-enabled until in-flight frames drain, then retire it.
    Requires LabKeys.sak2 (KN=2 lands on AN=1).
    """
    if not keys.sak2:
        raise ValueError("mka_rekey needs LabKeys.sak2 (second SAK)")
    a, b = keys.a, keys.b
    keys2 = replace(keys, sak=keys.sak2, kn=2, an=1)
    wrapped2 = wrap_sak(keys.kek, keys.sak2)
    frames: list[tuple[str, bytes]] = []

    def _mk(peer, mn: int, key_server: bool, param_sets, label: str) -> tuple[str, bytes]:
        return (
            label,
            build_mkpdu_frame(sa=peer.mac, ick=keys.ick, basic=_basic(peer, keys, mn, key_server), param_sets=param_sets),
        )

    # --- steady state on SAK#1 (AN=0, KN=1) ---
    frames.append(_mk(a, 4, True, [
        PeerList(1, [PeerTuple(b.mi, 3)]),
        _sak_use((0, True, True), a.mi, 1, 10),
    ], "A MN=4 keepalive on SAK#1 (steady state, AN=0 KN=1)"))
    user = ipv4_icmp_echo("10.10.0.10", "10.10.0.20", ident=0x4242, seq=10)
    tag = SecTAG.build(pn=10, an=keys.an, encrypt=True, sci=a.sci)
    frames.append((
        "A→B data PN=10 AN=0 with SAK#1 (PN keeps climbing toward exhaustion)",
        protect_frame(b.mac, a.mac, user, keys.sak, tag, a.sci),
    ))
    frames.append(_mk(b, 4, False, [
        PeerList(1, [PeerTuple(a.mi, 4)]),
        _sak_use((0, True, True), a.mi, 1, 10),
    ], "B MN=4 keepalive on SAK#1"))

    # --- Key Server rolls to SAK#2 (AN=1, KN=2) ---
    frames.append(_mk(a, 5, True, [
        DistributedSak(an=keys2.an, confidentiality_offset=0, kn=keys2.kn, wrapped_sak=wrapped2),
        PeerList(1, [PeerTuple(b.mi, 4)]),
        _sak_use((1, True, False), a.mi, 2, 1, old=(0, True, True), old_kn=1, old_lpn=10),
    ], "A MN=5 rekey: Distributed SAK#2 (AN=1 KN=2) + SAK Use latest=AN1 tx / old=AN0 tx+rx"))
    frames.append(_mk(b, 5, False, [
        PeerList(1, [PeerTuple(a.mi, 5)]),
        _sak_use((1, True, True), a.mi, 2, 1, old=(0, True, True), old_kn=1, old_lpn=10),
    ], "B MN=5 installed SAK#2: SAK Use latest=AN1 tx+rx / old=AN0 tx+rx"))
    frames.append(_mk(a, 6, True, [
        PeerList(1, [PeerTuple(b.mi, 5)]),
        _sak_use((1, True, True), a.mi, 2, 1, old=(0, False, True), old_kn=1, old_lpn=10),
    ], "A MN=6 stopped tx on SAK#1: latest=AN1 tx+rx / old=AN0 rx-only (drain)"))

    # --- data on the new SA: PN restarts at 1 in each direction (own SCI/SA) ---
    for src, dst, src_ip, dst_ip, sci in [
        (a, b, "10.10.0.10", "10.10.0.20", a.sci),
        (b, a, "10.10.0.20", "10.10.0.10", b.sci),
    ]:
        user = ipv4_icmp_echo(src_ip, dst_ip, ident=0x4242, seq=11)
        tag = SecTAG.build(pn=1, an=keys2.an, encrypt=True, sci=sci)
        frames.append((
            f"{'A→B' if src is a else 'B→A'} data PN=1 AN=1 with SAK#2 — PN restarts at 1 "
            "(each direction is its own SA with a fresh replay window)",
            protect_frame(dst.mac, src.mac, user, keys2.sak, tag, sci),
        ))

    # --- old SA retired ---
    frames.append(_mk(b, 7, False, [
        PeerList(1, [PeerTuple(a.mi, 6)]),
        _sak_use((1, True, True), a.mi, 2, 2),
    ], "B MN=7 keepalive on SAK#2; old SA retired (old KN=0)"))
    return frames


def mka_co30(keys: LabKeys) -> list[tuple[str, bytes]]:
    """Confidentiality-offset story: KS hands out SAK#3 with co=30 (AN=2, KN=3).

    With offset 30 the first 30 octets of User Data (inner EtherType + IPv4
    header + 8 octets of L4 header) are authenticated but travel in clear;
    GCM encrypts only the remainder. The offset is signaled in the
    Distributed SAK parameter set (code 1 = 30), never in the SecTAG.
    Requires LabKeys.sak3.
    """
    if not keys.sak3:
        raise ValueError("mka_co30 needs LabKeys.sak3")
    a, b = keys.a, keys.b
    keys3 = replace(keys, sak=keys.sak3, kn=3, an=2)
    wrapped3 = wrap_sak(keys.kek, keys.sak3)
    frames: list[tuple[str, bytes]] = []

    frames.append((
        "A MN=8: Distributed SAK#3 with confidentiality offset code 1 (=30 octets, AN=2 KN=3)",
        build_mkpdu_frame(
            sa=a.mac,
            ick=keys.ick,
            basic=_basic(a, keys, 8, True),
            param_sets=[
                DistributedSak(an=keys3.an, confidentiality_offset=1, kn=keys3.kn, wrapped_sak=wrapped3),
                PeerList(1, [PeerTuple(b.mi, 7)]),
                _sak_use((2, True, False), a.mi, 3, 1),
            ],
        ),
    ))
    for src, dst, src_ip, dst_ip, sci in [
        (a, b, "10.10.0.10", "10.10.0.20", a.sci),
        (b, a, "10.10.0.20", "10.10.0.10", b.sci),
    ]:
        user = ipv4_icmp_echo(src_ip, dst_ip, ident=0x4242, seq=12)
        tag = SecTAG.build(pn=1, an=keys3.an, encrypt=True, sci=sci)
        frames.append((
            f"{'A→B' if src is a else 'B→A'} data PN=1 AN=2 co=30 with SAK#3 — inner EtherType+IPv4+8 "
            "octets travel in clear (still ICV-protected), only the payload is encrypted",
            protect_frame(dst.mac, src.mac, user, keys3.sak, tag, sci, confidentiality_offset=30),
        ))
    frames.append((
        "B MN=8 keepalive: SAK Use latest=AN2 tx+rx (installed SAK#3)",
        build_mkpdu_frame(
            sa=b.mac,
            ick=keys.ick,
            basic=_basic(b, keys, 8, False),
            param_sets=[
                PeerList(1, [PeerTuple(a.mi, 8)]),
                _sak_use((2, True, True), a.mi, 3, 1),
            ],
        ),
    ))
    return frames


def macsec_lab_data(keys: LabKeys, encrypt: bool) -> list[tuple[str, bytes]]:
    a, b = keys.a, keys.b
    frames: list[tuple[str, bytes]] = []
    for seq in range(1, 4):
        user = ipv4_icmp_echo("10.10.0.10", "10.10.0.20", ident=0x4242, seq=seq)
        tag = SecTAG.build(pn=seq, an=keys.an, encrypt=encrypt, sci=a.sci)
        frames.append(
            (
                f"A→B ICMP echo seq={seq} ({'encrypted' if encrypt else 'integrity-only'})",
                protect_frame(b.mac, a.mac, user, keys.sak, tag, a.sci),
            )
        )
        reply = ipv4_icmp_echo("10.10.0.20", "10.10.0.10", ident=0x4242, seq=seq)
        # ICMP echo reply type=0: rebuild with type 0 by flipping first icmp byte after IP
        # ipv4_icmp_echo always uses type 8; for learning, echo request both ways is fine.
        tag_b = SecTAG.build(pn=seq, an=keys.an, encrypt=encrypt, sci=b.sci)
        frames.append(
            (
                f"B→A ICMP seq={seq} ({'encrypted' if encrypt else 'integrity-only'})",
                protect_frame(a.mac, b.mac, reply, keys.sak, tag_b, b.sci),
            )
        )
    # Point-to-point encoding without explicit SCI (ES=1, SC=0)
    user = ipv4_icmp_echo("10.10.0.10", "10.10.0.20", ident=0x4242, seq=9)
    tag_es = SecTAG.build(pn=9, an=keys.an, encrypt=encrypt, sci=None, es=True)
    frames.append(
        (
            f"A→B ES=1 no-SCI PN=9 ({'encrypted' if encrypt else 'integrity-only'})",
            protect_frame(b.mac, a.mac, user, keys.sak, tag_es, a.sci),
        )
    )
    return frames


def ieee_integrity_frame() -> bytes:
    tag = SecTAG(tci=0x22, sl=0x2A, pn=IEEE_PN, sci=IEEE_SCI)
    return protect_frame(IEEE_DA, IEEE_SA, IEEE_INT_USER, IEEE_GCM_KEY_128, tag, IEEE_SCI)


def ieee_encrypt_frame() -> bytes:
    tag = SecTAG(tci=0x2E, sl=0, pn=IEEE_PN, sci=IEEE_SCI)
    return protect_frame(IEEE_DA, IEEE_SA, IEEE_ENC_USER, IEEE_GCM_KEY_128, tag, IEEE_SCI)


def ieee256_integrity_frame() -> bytes:
    """Same 54-byte frame as the 128-bit vector, but GCM-AES-256 (Randall 2.1.2)."""
    tag = SecTAG(tci=0x22, sl=0x2A, pn=IEEE_PN, sci=IEEE_SCI)
    return protect_frame(IEEE_DA, IEEE_SA, IEEE_INT_USER, IEEE_GCM_KEY_256, tag, IEEE_SCI)


def ieee256_encrypt_frame() -> bytes:
    """Same 60-byte frame as the 128-bit vector, but GCM-AES-256 (Randall 2.2.2)."""
    tag = SecTAG(tci=0x2E, sl=0, pn=IEEE_PN, sci=IEEE_SCI)
    return protect_frame(IEEE_DA, IEEE_SA, IEEE_ENC_USER, IEEE_GCM_KEY_256, tag, IEEE_SCI)
