"""Reference frame sequences for the learning captures."""

from __future__ import annotations

from dataclasses import replace

from .crypto import assign_sscis, wrap_sak, xpn_default_salt, xpn_iv
from .keys import (
    CS_GCM_AES_XPN_128,
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
    Peer,
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


def _basic(peer, keys: LabKeys, mn: int, key_server: bool, version: int = 2) -> BasicParamSet:
    """Basic Parameter Set shared by every MKPDU story.

    MKA version 2 = 802.1X-2010 (handshake / rekey / co30 stories); the XPN
    story uses version 3 (802.1X-2020), the version the Key Server SSCI byte
    in Live Peer Lists belongs to.
    """
    return BasicParamSet(
        version=version,
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


# The XPN story starts with the SA having already used the first 2^32 PNs —
# that is the situation XPN exists for (32-bit suites would have to rekey).
XPN_INITIAL_PN64_HIGH = 1


def mka_xpn(keys: LabKeys) -> list[tuple[str, bytes]]:
    """XPN cipher-suite story: SAK#4 as GCM-AES-XPN-128 (AN=3, KN=4).

    Continues the PSK story (MN 1-8 are handshake / rekey / co30). The Key
    Server rolls to the XPN suite, so this Distributed SAK is the first (and
    only) one that carries the 8-octet cipher suite ID — body length 36
    instead of the default suite's 28. Data frames then cross the 2^32
    boundary: the on-wire PN wraps FFFFFFFF -> 00000001 while the real
    64-bit PN keeps climbing, and the nonce is (SSCI || PN64) XOR Salt
    instead of SCI || PN. Requires LabKeys.sak4.
    """
    if not keys.sak4:
        raise ValueError("mka_xpn needs LabKeys.sak4 (XPN SAK)")
    a, b = keys.a, keys.b
    ssci = assign_sscis([a.sci, b.sci])  # deterministic: largest SCI -> 0x0001
    salt = xpn_default_salt(a.sci)
    keys4 = replace(keys, sak=keys.sak4, kn=4, an=3)
    wrapped4 = wrap_sak(keys.kek, keys.sak4)
    frames: list[tuple[str, bytes]] = []

    frames.append((
        "A MN=9 (MKA version 3, 802.1X-2020) rekey to XPN suite: Distributed SAK#4 carries "
        "cipher suite 00-80-C2-00-01-00-00-03 (body length 36; default suite omits the ID, 28)",
        build_mkpdu_frame(
            sa=a.mac,
            ick=keys.ick,
            basic=_basic(a, keys, 9, True, version=3),
            param_sets=[
                DistributedSak(
                    an=keys4.an,
                    confidentiality_offset=0,
                    kn=keys4.kn,
                    wrapped_sak=wrapped4,
                    cipher_suite=CS_GCM_AES_XPN_128,
                ),
                PeerList(1, [PeerTuple(b.mi, 8)], key_server_ssci=ssci[a.sci]),
                _sak_use((3, True, False), a.mi, 4, 1, old=(2, False, True), old_kn=3, old_lpn=1),
            ],
        ),
    ))
    frames.append((
        f"B MN=9 installed XPN SAK#4: SAK Use latest=AN3 tx+rx; peer-list byte "
        f"now carries B's own SSCI LSB 0x{ssci[b.sci]:02x} (非 XPN 故事里是 0)",
        build_mkpdu_frame(
            sa=b.mac,
            ick=keys.ick,
            basic=_basic(b, keys, 9, False, version=3),
            param_sets=[
                PeerList(1, [PeerTuple(a.mi, 9)], key_server_ssci=ssci[b.sci]),
                _sak_use((3, True, True), a.mi, 4, 1, old=(2, False, True), old_kn=3, old_lpn=1),
            ],
        ),
    ))

    # --- data plane: cross the 2^32 boundary without a rekey ---
    xpn_data = [
        (a, b, "10.10.0.10", "10.10.0.20", (XPN_INITIAL_PN64_HIGH << 32) | 0xFFFFFFFF, 13,
         "A→B PN64=0x1FFFFFFFF: the LAST frame of the first 2^32 epoch — a 32-bit "
         "suite would have to rekey here, XPN keeps going"),
        (a, b, "10.10.0.10", "10.10.0.20", ((XPN_INITIAL_PN64_HIGH + 1) << 32) | 1, 14,
         "A→B PN64=0x200000001: on-wire PN wrapped to 0x00000001; receiver recovers the "
         "high half from SA state (802.1AE 10.6), same SAK, no MKA churn"),
        (b, a, "10.10.0.20", "10.10.0.10", (XPN_INITIAL_PN64_HIGH << 32) | 3, 15,
         "B→A PN64=0x100000003: own SA, own SSCI, own PN64 space — the nonce is per-SC"),
    ]
    for src, dst, src_ip, dst_ip, pn64, seq, label in xpn_data:
        user = ipv4_icmp_echo(src_ip, dst_ip, ident=0x4242, seq=seq)
        tag = SecTAG.build(pn=pn64 & 0xFFFFFFFF, an=keys4.an, encrypt=True, sci=src.sci)
        iv = xpn_iv(ssci[src.sci], pn64, salt)
        frames.append((label, protect_frame(dst.mac, src.mac, user, keys4.sak, tag, src.sci, iv=iv)))

    frames.append((
        "B MN=10 keepalive on the XPN SA: everything above 2^32 is business as usual",
        build_mkpdu_frame(
            sa=b.mac,
            ick=keys.ick,
            basic=_basic(b, keys, 10, False, version=3),
            param_sets=[
                PeerList(1, [PeerTuple(a.mi, 9)], key_server_ssci=ssci[b.sci]),
                _sak_use((3, True, True), a.mi, 4, 2),
            ],
        ),
    ))
    return frames


def multi_peer_c(keys: LabKeys) -> Peer:
    """Third member of the shared-CAK CA (mka-multi-peer story): node-c.

    Same CAK/CKN as node-a/node-b — one Connectivity Association, three
    members, Key Server still node-a (priority 16 < 32 < 48).
    """
    return Peer.make(
        "node-c",
        bytes.fromhex("02000000000c"),
        1,
        48,
        bytes.fromhex("cc11cc12cc13cc14cc15cc16"),
    )


def mka_multi_peer(keys: LabKeys) -> list[tuple[str, bytes]]:
    """Shared-CAK multi-member CA: node-a/b/c, one Key Server, ONE SAK.

    A CA is not inherently point-to-point: every member configured with the
    same CAK/CKN joins the same CA. The elected Key Server distributes a
    single SAK once (group-keyed), and every member transmits on its own SC —
    so the receiver side instantiates one RX SA per remote member, keyed by
    (SCI, AN). Two consequences visible in this capture:

    - every data frame carries an explicit SCI (SC=1) — the ES=1 "point-to-
      point, SCI omitted" shortcut is only valid when exactly two members
      share the CA;
    - three frames with PN=1 coexist (one per SC) without being a replay.
    """
    a, b = keys.a, keys.b
    c = multi_peer_c(keys)
    wrapped = wrap_sak(keys.kek, keys.sak)
    frames: list[tuple[str, bytes]] = []

    def _p(peer, mn: int, key_server: bool, param_sets, label: str):
        return (
            label,
            build_mkpdu_frame(
                sa=peer.mac, ick=keys.ick, basic=_basic(peer, keys, mn, key_server),
                param_sets=param_sets,
            ),
        )

    frames.append(_p(a, 1, True, [], "A MN=1 hello (Key Server claim, prio 16 — smallest priority wins)"))
    frames.append(_p(
        b, 1, False, [PeerList(2, [PeerTuple(a.mi, 1)])],
        "B MN=1 hello (Potential Peer List: A; prio 32)",
    ))
    frames.append(_p(
        c, 1, False, [PeerList(2, [PeerTuple(a.mi, 1), PeerTuple(b.mi, 1)])],
        "C MN=1 hello (Potential Peer List: A + B; prio 48 — three members, one CAK/CKN)",
    ))
    frames.append(_p(
        a, 2, True,
        [
            DistributedSak(an=keys.an, confidentiality_offset=0, kn=keys.kn, wrapped_sak=wrapped),
            SakUse(
                latest_an=keys.an, latest_tx=True, latest_rx=False, delay_protect=True,
                latest_server_mi=a.mi, latest_kn=keys.kn, latest_lpn=1,
            ),
            PeerList(1, [PeerTuple(b.mi, 1), PeerTuple(c.mi, 1)]),
        ],
        "A MN=2 Key Server: ONE Distributed SAK for the whole CA + SAK Use (tx) "
        "+ Live Peer List with TWO tuples",
    ))
    frames.append(_p(
        b, 2, False,
        [
            SakUse(
                latest_an=keys.an, latest_tx=True, latest_rx=True, delay_protect=True,
                latest_server_mi=a.mi, latest_kn=keys.kn, latest_lpn=1,
            ),
            PeerList(1, [PeerTuple(a.mi, 2), PeerTuple(c.mi, 1)]),
        ],
        "B MN=2: SAK Use tx+rx (installed the SAK); Live Peer List [A, C]",
    ))
    frames.append(_p(
        c, 2, False,
        [
            SakUse(
                latest_an=keys.an, latest_tx=True, latest_rx=True, delay_protect=True,
                latest_server_mi=a.mi, latest_kn=keys.kn, latest_lpn=1,
            ),
            PeerList(1, [PeerTuple(a.mi, 2), PeerTuple(b.mi, 2)]),
        ],
        "C MN=2: SAK Use tx+rx; Live Peer List [A, B]",
    ))
    frames.append(_p(
        a, 3, True,
        [
            SakUse(
                latest_an=keys.an, latest_tx=True, latest_rx=True, delay_protect=True,
                latest_server_mi=a.mi, latest_kn=keys.kn, latest_lpn=1,
            ),
            PeerList(1, [PeerTuple(b.mi, 2), PeerTuple(c.mi, 2)]),
        ],
        "A MN=3: SAK Use tx+rx — all three members live on the single SAK",
    ))

    # All-to-all data plane: each member sends from its own SC (own SCI, own
    # PN space) on the same SAK. Explicit SCI is mandatory here (SC=1).
    ips = {a.mac: "10.10.0.10", b.mac: "10.10.0.20", c.mac: "10.10.0.30"}
    seq = 20
    for src, dst in [(a, b), (b, c), (c, a)]:
        user = ipv4_icmp_echo(ips[src.mac], ips[dst.mac], ident=0x4242, seq=seq)
        tag = SecTAG.build(pn=1, an=keys.an, encrypt=True, sci=src.sci)
        frames.append((
            f"{src.name[-1].upper()}→{dst.name[-1].upper()} data PN=1 AN=0 SC=1 "
            f"ICMP seq={seq} — {src.name}'s own SC/SCI; explicit SCI because the CA "
            f"has more than two members",
            protect_frame(dst.mac, src.mac, user, keys.sak, tag, src.sci),
        ))
        seq += 1

    frames.append(_p(
        c, 3, False,
        [
            SakUse(
                latest_an=keys.an, latest_tx=True, latest_rx=True, delay_protect=True,
                latest_server_mi=a.mi, latest_kn=keys.kn, latest_lpn=1,
            ),
            PeerList(1, [PeerTuple(a.mi, 3), PeerTuple(b.mi, 2)]),
        ],
        "C MN=3 keepalive: one CAK, one KS, one SAK, three unidirectional SCs",
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


def macsec_replay(keys: LabKeys) -> list[tuple[str, bytes]]:
    """Receiver replay-window story: what B's RX SA does with A's stream.

    Runs a small window (2) on B's receive SA for A's SC so every verdict
    class shows up in nine frames: in-order, gap + late reorder (accepted
    inside the window), a stale replay below the floor (dropped), and a
    duplicate inside the window (dropped). Replayed frames are byte-identical
    to the originals — same PN means same GCM nonce, so ciphertext and ICV
    are unchanged and still verify. Nothing cryptographic flags a replay;
    only the PN window does. Verdicts live in the frame comments; the model
    is macsec_lab.macsec.ReplayWindow (see docs/lifecycle.md §3).
    """
    a, b = keys.a, keys.b

    def _data(pn: int, seq: int) -> bytes:
        user = ipv4_icmp_echo("10.10.0.10", "10.10.0.20", ident=0x4242, seq=seq)
        tag = SecTAG.build(pn=pn, an=keys.an, encrypt=True, sci=a.sci)
        return protect_frame(b.mac, a.mac, user, keys.sak, tag, a.sci)

    spec: list[tuple[int, int, str]] = [
        (1, 1, "A→B PN=1 — in order, accepted; window advances"),
        (2, 2, "A→B PN=2 — in order, accepted"),
        (3, 3, "A→B PN=3 — in order, accepted (remember this frame)"),
        (5, 5, "A→B PN=5 — PN=4 missing (lost/reordered); PN=5 accepted, "
               "window slides: floor is now PN=3"),
        (4, 4, "A→B PN=4 arrives late — inside the window (floor=3 < 4 < next=6), "
               "accepted as reordered"),
        (3, 3, "REPLAY of frame 3, byte-identical, ICV still verifies — DROPPED: "
               "PN=3 <= floor(3), below the replay window"),
        (6, 6, "A→B PN=6 — in order, accepted"),
        (6, 6, "DUPLICATE of the previous frame — DROPPED: PN=6 already seen "
               "inside the window"),
        (7, 7, "A→B PN=7 — in order, accepted; the replay attempts never advanced "
               "the window"),
    ]
    return [(label, _data(pn, seq)) for pn, seq, label in spec]


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
