"""IEEE 802.1AE GCM-AES-128 published test vectors + lab round-trip."""

from __future__ import annotations

import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from macsec_lab.crypto import (
    assign_sscis,
    derive_eap_cak,
    derive_eap_ckn,
    gcm_protect,
    gcm_validate,
    xpn_default_salt,
    xpn_iv,
)
from macsec_lab.keys import (
    CS_GCM_AES_XPN_128,
    EAPOL_TYPE_EAP,
    IEEE_DA,
    IEEE_ENC_CT_128,
    IEEE_ENC_CT_256,
    IEEE_ENC_ICV_128,
    IEEE_ENC_ICV_256,
    IEEE_ENC_USER,
    IEEE_GCM_KEY_128,
    IEEE_GCM_KEY_256,
    IEEE_INT_ICV_128,
    IEEE_INT_ICV_256,
    IEEE_INT_USER,
    IEEE_PN,
    IEEE_SA,
    IEEE_SCI,
    LabKeys,
)
from macsec_lab.l3 import ipv4_icmp_echo
from macsec_lab.macsec import SecTAG, XpnPnTracker, parse_frame, protect_frame
from macsec_lab.dissect import dissect_eap, dissect_macsec, dissect_mka
from macsec_lab.mka import parse_eapol_mka
from macsec_lab.scenario import (
    XPN_INITIAL_PN64_HIGH,
    ieee_encrypt_frame,
    ieee_integrity_frame,
    ieee256_encrypt_frame,
    ieee256_integrity_frame,
    macsec_lab_data,
    mka_after_eap,
    mka_co30,
    mka_handshake,
    mka_rekey,
    mka_xpn,
)


class IeeeVectors(unittest.TestCase):
    def test_integrity_only_icv(self) -> None:
        frame = ieee_integrity_frame()
        self.assertEqual(frame[-16:], IEEE_INT_ICV_128)
        parsed = parse_frame(frame, IEEE_GCM_KEY_128)
        self.assertTrue(parsed["icv_ok"])
        self.assertEqual(parsed["user_data"], IEEE_INT_USER)
        self.assertEqual(parsed["tag"].tci, 0x22)
        self.assertEqual(parsed["da"], IEEE_DA)
        self.assertEqual(parsed["sa"], IEEE_SA)

    def test_confidentiality_icv_and_ciphertext(self) -> None:
        frame = ieee_encrypt_frame()
        tag, n = SecTAG.unpack(frame[14:])
        self.assertEqual(n, 14)
        secure = frame[14 + n : -16]
        self.assertEqual(secure, IEEE_ENC_CT_128)
        self.assertEqual(frame[-16:], IEEE_ENC_ICV_128)
        parsed = parse_frame(frame, IEEE_GCM_KEY_128)
        self.assertTrue(parsed["icv_ok"])
        self.assertEqual(parsed["user_data"], IEEE_ENC_USER)
        self.assertEqual(parsed["tag"].pn, IEEE_PN)
        self.assertEqual(parsed["sci"], IEEE_SCI)


class IeeeVectors256(unittest.TestCase):
    """Same published frames, 256-bit key (Randall 2.1.2 / 2.2.2)."""

    def test_integrity_only_icv_256(self) -> None:
        frame = ieee256_integrity_frame()
        self.assertEqual(frame[-16:], IEEE_INT_ICV_256)
        parsed = parse_frame(frame, IEEE_GCM_KEY_256)
        self.assertTrue(parsed["icv_ok"])
        self.assertEqual(parsed["user_data"], IEEE_INT_USER)
        # Same frame, wrong key size -> cannot validate
        self.assertFalse(parse_frame(frame, IEEE_GCM_KEY_128)["icv_ok"])

    def test_confidentiality_ct_and_icv_256(self) -> None:
        frame = ieee256_encrypt_frame()
        tag, n = SecTAG.unpack(frame[14:])
        self.assertEqual(frame[14 + n : -16], IEEE_ENC_CT_256)
        self.assertEqual(frame[-16:], IEEE_ENC_ICV_256)
        parsed = parse_frame(frame, IEEE_GCM_KEY_256)
        self.assertTrue(parsed["icv_ok"])
        self.assertEqual(parsed["user_data"], IEEE_ENC_USER)


class XpnIv(unittest.TestCase):
    """XPN nonce construction (802.1AEbw-2013): IV = (SSCI || PN64) XOR Salt."""

    SALT = bytes.fromhex("e630e81a48df000000000000")  # Randall draft C-11 salt + zeros
    SSCI = 0x0001
    PN64 = 0xB0DF459C_B2C28465  # 32 MSBs from the draft + the SecTAG PN

    def test_iv_layout_and_xor(self) -> None:
        iv = xpn_iv(self.SSCI, self.PN64, self.SALT)
        self.assertEqual(len(iv), 12)
        raw = self.SSCI.to_bytes(4, "big") + self.PN64.to_bytes(8, "big")
        self.assertEqual(iv, bytes(a ^ b for a, b in zip(raw, self.SALT)))
        # Low 32 bits of PN64 are what the SecTAG carries
        self.assertEqual(self.PN64 & 0xFFFFFFFF, IEEE_PN)

    def test_xpn_gcm_roundtrip_and_salt_sensitivity(self) -> None:
        iv = xpn_iv(self.SSCI, self.PN64, self.SALT)
        aad = IEEE_DA + IEEE_SA + b"\x88\xe5" + SecTAG(tci=0x2E, sl=0, pn=IEEE_PN, sci=IEEE_SCI).pack()
        ct, icv = gcm_protect(IEEE_GCM_KEY_128, iv, aad, IEEE_ENC_USER)
        self.assertEqual(gcm_validate(IEEE_GCM_KEY_128, iv, aad, ct, icv), IEEE_ENC_USER)
        other = xpn_iv(self.SSCI, self.PN64, bytes(12))
        self.assertNotEqual(iv, other, "salt must change the nonce")
        with self.assertRaises(Exception):
            gcm_validate(IEEE_GCM_KEY_128, other, aad, ct, icv)

    def test_xpn_iv_rejects_bad_sizes(self) -> None:
        with self.assertRaises(ValueError):
            xpn_iv(2**32, 1, bytes(12))
        with self.assertRaises(ValueError):
            xpn_iv(1, 2**64, bytes(12))
        with self.assertRaises(ValueError):
            xpn_iv(1, 1, bytes(11))


class LabRoundTrip(unittest.TestCase):
    def test_mka_icv_and_sak_unwrap(self) -> None:
        keys = LabKeys.default()
        frames = mka_handshake(keys)
        self.assertGreaterEqual(len(frames), 4)
        saw_sak = False
        for comment, raw in frames:
            p = parse_eapol_mka(raw, keys.ick, keys.kek)
            self.assertTrue(p["icv_ok"], comment)
            self.assertEqual(p["basic"].ckn, keys.ckn)
            if p["unwrapped_sak"] is not None:
                self.assertEqual(p["unwrapped_sak"], keys.sak)
                saw_sak = True
        self.assertTrue(saw_sak, "Distributed SAK missing")

    def test_lab_encrypted_decrypts(self) -> None:
        keys = LabKeys.default()
        for comment, raw in macsec_lab_data(keys, encrypt=True):
            p = parse_frame(raw, keys.sak, keys.a.sci if raw[6:12] == keys.a.mac else keys.b.sci)
            self.assertTrue(p["icv_ok"], comment)
            self.assertTrue(p["tag"].e)
            self.assertIsNotNone(p["user_data"])
            self.assertEqual(p["user_data"][:2], b"\x08\x00")

    def test_lab_integrity_payload_visible(self) -> None:
        keys = LabKeys.default()
        for comment, raw in macsec_lab_data(keys, encrypt=False):
            p = parse_frame(raw, keys.sak, keys.a.sci if raw[6:12] == keys.a.mac else keys.b.sci)
            self.assertTrue(p["icv_ok"], comment)
            self.assertFalse(p["tag"].e)
            self.assertEqual(p["user_data"][:2], b"\x08\x00")

    def test_key_server_election_visible(self) -> None:
        keys = LabKeys.default()
        frames = mka_handshake(keys)
        a_first = parse_eapol_mka(frames[0][1], keys.ick)
        b_first = parse_eapol_mka(frames[1][1], keys.ick)
        self.assertTrue(a_first["basic"].key_server)
        self.assertFalse(b_first["basic"].key_server)
        self.assertLess(a_first["basic"].ks_priority, b_first["basic"].ks_priority)

    def test_every_mka_message_has_offset_map(self) -> None:
        keys = LabKeys.default()
        for comment, raw in mka_handshake(keys):
            title, fields, parsed = dissect_mka(raw, keys)
            self.assertTrue(fields, comment)
            self.assertIn("ICV", title)
            last = max(f.offset + f.length for f in fields if f.length)
            self.assertGreaterEqual(last, parsed["wire_len"], comment)
            names = [f.name for f in fields]
            self.assertIn("CKN", names, comment)
            self.assertIn("MKA ICV", names, comment)

    def test_every_macsec_message_has_inner_ip(self) -> None:
        keys = LabKeys.default()
        for comment, raw in macsec_lab_data(keys, encrypt=True):
            title, fields, parsed, inner = dissect_macsec(raw, keys.sak, keys.a.sci, keys.b.sci)
            self.assertTrue(parsed["icv_ok"], comment)
            inner_names = [f.name for f in inner]
            self.assertIn("ICMP Sequence", inner_names, comment)
            self.assertIn("IP Src", inner_names, comment)


class SakRekey(unittest.TestCase):
    def test_rekey_distributes_second_sak_on_an1(self) -> None:
        keys = LabKeys.default()
        self.assertTrue(keys.sak2)
        frames = mka_rekey(keys)
        self.assertEqual(len(frames), 9)
        saw = []
        for comment, raw in frames:
            if int.from_bytes(raw[12:14], "big") != 0x888E:
                continue
            p = parse_eapol_mka(raw, keys.ick, keys.kek)
            self.assertTrue(p["icv_ok"], comment)
            if p["unwrapped_sak"] is not None:
                saw.append((p, comment))
        self.assertEqual(len(saw), 1, "exactly one Distributed SAK in the rekey story")
        p, comment = saw[0]
        self.assertEqual(p["unwrapped_sak"], keys.sak2, comment)
        ds = next(s["body"] for s in p["param_sets"] if s["code"] == 4)
        self.assertEqual(ds.an, 1)
        self.assertEqual(ds.kn, 2)

    def test_rekey_data_uses_an_and_pn_per_sa(self) -> None:
        keys = LabKeys.default()
        data = [(c, r) for c, r in mka_rekey(keys) if int.from_bytes(r[12:14], "big") == 0x88E5]
        sak_by_an = {0: keys.sak, 1: keys.sak2}
        ans = []
        for comment, raw in data:
            hint = keys.a.sci if raw[6:12] == keys.a.mac else keys.b.sci
            p = parse_frame(raw, sak_by_an[raw[14] & 0x03], hint)
            self.assertTrue(p["icv_ok"], comment)
            self.assertEqual(p["user_data"][:2], b"\x08\x00", comment)
            ans.append((p["tag"].an, p["tag"].pn))
        # Old SA: PN keeps climbing; new SA: PN restarts at 1 with a different key.
        self.assertEqual(ans[0], (0, 10))
        self.assertEqual(ans[1], (1, 1))
        self.assertEqual(ans[2], (1, 1))

    def test_rekey_sak_use_transitions(self) -> None:
        keys = LabKeys.default()
        frames = mka_rekey(keys)
        uses = []
        for comment, raw in frames:
            if int.from_bytes(raw[12:14], "big") != 0x888E:
                continue
            p = parse_eapol_mka(raw, keys.ick)
            for s in p["param_sets"]:
                if s["code"] == 3:
                    uses.append(s["body"])
        # steady state: latest AN0 tx+rx, no old SA in use
        self.assertEqual((uses[0].latest_an, uses[0].latest_tx, uses[0].latest_rx), (0, True, True))
        self.assertEqual((uses[0].old_tx, uses[0].old_rx, uses[0].old_kn), (False, False, 0))
        # KS distributes SAK#2 (uses[2] = A MN=5): latest=AN1 tx, still old tx+rx
        self.assertEqual((uses[2].latest_an, uses[2].latest_tx, uses[2].latest_rx), (1, True, False))
        self.assertEqual((uses[2].old_an, uses[2].old_tx, uses[2].old_rx, uses[2].old_kn), (0, True, True, 1))
        # peer installs SAK#2 (uses[3] = B MN=5): latest=AN1 tx+rx
        self.assertEqual((uses[3].latest_tx, uses[3].latest_rx), (True, True))
        # KS stops transmitting on old SA (uses[4] = A MN=6): old rx-only drain
        self.assertEqual((uses[4].old_tx, uses[4].old_rx), (False, True))
        # final keepalive: old SA fully retired
        self.assertEqual((uses[-1].old_tx, uses[-1].old_rx, uses[-1].old_kn), (False, False, 0))


class ConfidentialityOffset(unittest.TestCase):
    def test_co30_roundtrip_clear_prefix_still_authenticated(self) -> None:
        keys = LabKeys.default()
        user = ipv4_icmp_echo("10.10.0.10", "10.10.0.20", ident=0x4242, seq=12)
        tag = SecTAG.build(pn=1, an=2, encrypt=True, sci=keys.a.sci)
        frame = protect_frame(
            keys.b.mac, keys.a.mac, user, keys.sak3, tag, keys.a.sci, confidentiality_offset=30
        )
        secure = frame[14 + 14 : -16]  # DA+SA+0x88E5+SecTAG(SC=1) then Secure Data
        # First 30 octets of User Data (EtherType+IPv4+8) travel in clear
        self.assertEqual(secure[:30], user[:30])
        self.assertIn(bytes([10, 10, 0, 10]), secure[:30], "inner source IP must be visible")
        # Only the tail is ciphertext
        self.assertNotEqual(secure[30:], user[30:])
        # Receiver must know the offset from MKA: with it, ICV+decrypt succeed
        p = parse_frame(frame, keys.sak3, confidentiality_offset=30)
        self.assertTrue(p["icv_ok"])
        self.assertEqual(p["user_data"], user)
        # Without the offset the same SAK cannot validate the frame
        p0 = parse_frame(frame, keys.sak3)
        self.assertFalse(p0["icv_ok"])
        # Tampering the clear prefix still breaks the ICV (it is in the AAD)
        tampered = bytearray(frame)
        tampered[14 + 14 + 25] ^= 0xFF
        self.assertFalse(parse_frame(bytes(tampered), keys.sak3, confidentiality_offset=30)["icv_ok"])

    def test_co30_story(self) -> None:
        keys = LabKeys.default()
        frames = mka_co30(keys)
        self.assertEqual(len(frames), 4)
        # Distributed SAK signals offset code 1 (=30 octets) on AN=2/KN=3
        p = parse_eapol_mka(frames[0][1], keys.ick, keys.kek)
        self.assertTrue(p["icv_ok"], frames[0][0])
        ds = next(s["body"] for s in p["param_sets"] if s["code"] == 4)
        self.assertEqual(ds.confidentiality_offset, 1)
        self.assertEqual((ds.an, ds.kn), (2, 3))
        self.assertEqual(p["unwrapped_sak"], keys.sak3)
        # Data frames decrypt with SAK#3 + co=30
        for comment, raw in frames[1:3]:
            hint = keys.a.sci if raw[6:12] == keys.a.mac else keys.b.sci
            q = parse_frame(raw, keys.sak3, hint, confidentiality_offset=30)
            self.assertTrue(q["icv_ok"], comment)
            self.assertEqual(q["user_data"], user_of(raw, keys))


def user_of(raw: bytes, keys: LabKeys) -> bytes:
    """Rebuild the ICMP user data a co30 data frame should decrypt to."""
    src_ip = "10.10.0.10" if raw[6:12] == keys.a.mac else "10.10.0.20"
    dst_ip = "10.10.0.20" if raw[6:12] == keys.a.mac else "10.10.0.10"
    return ipv4_icmp_echo(src_ip, dst_ip, ident=0x4242, seq=12)


class MermaidLabels(unittest.TestCase):
    def test_protocol_analysis_mermaid_messages_are_english(self) -> None:
        from macsec_lab.analyze import protocol_analysis_doc

        text = protocol_analysis_doc("# x\n")
        start = text.index("```mermaid")
        end = text.index("```", start + 10)
        block = text[start:end]
        self.assertNotRegex(block, r"[\u4e00-\u9fff]")


class EapDerivedCak(unittest.TestCase):
    def test_cak_ckn_from_msk(self) -> None:
        keys = LabKeys.eap_default()
        self.assertEqual(len(keys.msk), 64)
        self.assertEqual(keys.cak, derive_eap_cak(keys.msk, keys.a.mac, keys.b.mac))
        self.assertEqual(
            keys.ckn,
            derive_eap_ckn(keys.msk, keys.a.mac, keys.b.mac, keys.eap_session_id),
        )
        self.assertEqual(len(keys.cak), 16)
        self.assertEqual(len(keys.ckn), 16)
        self.assertNotEqual(keys.cak, LabKeys.default().cak)
        self.assertNotEqual(keys.ckn, LabKeys.default().ckn)

    def test_authenticator_is_key_server(self) -> None:
        keys = LabKeys.eap_default()
        self.assertEqual(keys.a.ks_priority, 0)
        self.assertEqual(keys.b.ks_priority, 255)
        frames = mka_after_eap(keys)
        self.assertEqual(frames[0][1][15], EAPOL_TYPE_EAP)
        self.assertEqual(frames[0][1][18], 3)  # EAP Success
        hello = parse_eapol_mka(frames[1][1], keys.ick)
        peer = parse_eapol_mka(frames[2][1], keys.ick)
        self.assertTrue(hello["basic"].key_server)
        self.assertFalse(peer["basic"].key_server)
        self.assertLess(hello["basic"].ks_priority, peer["basic"].ks_priority)
        self.assertEqual(hello["basic"].ckn, keys.ckn)

    def test_mka_after_eap_icv_and_sak(self) -> None:
        keys = LabKeys.eap_default()
        frames = mka_after_eap(keys)
        self.assertEqual(len(frames), 7)
        title, fields, parsed = dissect_eap(frames[0][1])
        self.assertIn("Success", title)
        self.assertTrue(any(f.name == "EAP Code" for f in fields))
        saw_sak = False
        for comment, raw in frames[1:]:
            p = parse_eapol_mka(raw, keys.ick, keys.kek)
            self.assertTrue(p["icv_ok"], comment)
            if p["unwrapped_sak"] is not None:
                self.assertEqual(p["unwrapped_sak"], keys.sak)
                saw_sak = True
        self.assertTrue(saw_sak)


class XpnStory(unittest.TestCase):
    """SAK#4 as GCM-AES-XPN-128: cipher-suite ID in Distributed SAK, SSCI/Salt
    nonce, and a PN64 crossing 2^32 with the on-wire PN wrapping."""

    def test_xpn_distributed_sak_carries_cipher_suite_id(self) -> None:
        keys = LabKeys.default()
        self.assertTrue(keys.sak4)
        p = parse_eapol_mka(mka_xpn(keys)[0][1], keys.ick, keys.kek)
        self.assertTrue(p["icv_ok"])
        ds = next(s["body"] for s in p["param_sets"] if s["code"] == 4)
        self.assertEqual(ds.cipher_suite, CS_GCM_AES_XPN_128)
        self.assertEqual((ds.an, ds.kn), (3, 4))
        self.assertEqual(p["unwrapped_sak"], keys.sak4)
        # Non-default suite -> 8-octet ID rides along: body 28 becomes 36.
        raw_ps = ds.pack()
        self.assertEqual(int.from_bytes(raw_ps[2:4], "big") & 0x0FFF, 36)
        self.assertEqual(len(ds.wrapped_sak), 24, "128-bit SAK + 8-octet wrap")
        # Default-suite stories omit the ID (body stays 28).
        d0 = next(
            s["body"] for s in parse_eapol_mka(mka_handshake(keys)[2][1], keys.ick)["param_sets"]
            if s["code"] == 4
        )
        self.assertIsNone(d0.cipher_suite)
        self.assertEqual(int.from_bytes(d0.pack()[2:4], "big") & 0x0FFF, 28)

    def test_xpn_default_salt_and_ssci_assignment(self) -> None:
        keys = LabKeys.default()
        salt = xpn_default_salt(keys.a.sci)
        self.assertEqual(len(salt), 12)
        xor = bytes(a ^ b for a, b in zip(keys.a.sci[:4], keys.a.sci[4:]))
        self.assertEqual(salt, xor + keys.a.sci)
        # Deterministic rule: largest SCI gets 0x0001, next 0x0002.
        ssci = assign_sscis([keys.a.sci, keys.b.sci])
        self.assertEqual(ssci[keys.b.sci], 0x0001)  # node-b SCI is larger
        self.assertEqual(ssci[keys.a.sci], 0x0002)
        # Peer-list SSCI LSB byte is non-zero in the XPN story (0 in others).
        xpn = parse_eapol_mka(mka_xpn(keys)[1][1], keys.ick)
        live = next(s for s in xpn["param_sets"] if s["code"] == 1)
        self.assertEqual(live["ssci"], 0x01)  # B's own SSCI LSB
        psk = parse_eapol_mka(mka_handshake(keys)[1][1], keys.ick)
        self.assertEqual(next(s for s in psk["param_sets"] if s["code"] == 2)["ssci"], 0)

    def test_xpn_data_wraps_2pow32_and_recovers(self) -> None:
        keys = LabKeys.default()
        ssci = assign_sscis([keys.a.sci, keys.b.sci])
        salt = xpn_default_salt(keys.a.sci)
        data = [(c, r) for c, r in mka_xpn(keys) if int.from_bytes(r[12:14], "big") == 0x88E5]
        self.assertEqual(len(data), 3)
        # On-wire PN is only the low 32 bits: ...FE+1 wraps to 1.
        self.assertEqual([int.from_bytes(r[16:20], "big") for _, r in data], [0xFFFFFFFF, 1, 3])
        # Receiver-side recovery (what analyze.py does): per-direction trackers.
        trackers = {
            keys.a.mac: XpnPnTracker(high=XPN_INITIAL_PN64_HIGH),
            keys.b.mac: XpnPnTracker(high=XPN_INITIAL_PN64_HIGH),
        }
        expected = [0x1FFFFFFFF, 0x200000001, 0x100000003]
        for (comment, raw), want_pn64 in zip(data, expected):
            src = raw[6:12]
            pn64 = trackers[src].update(int.from_bytes(raw[16:20], "big"))
            self.assertEqual(pn64, want_pn64, comment)
            iv = xpn_iv(ssci[keys.a.sci if src == keys.a.mac else keys.b.sci], pn64, salt)
            p = parse_frame(raw, keys.sak4, keys.a.sci if src == keys.a.mac else keys.b.sci, iv=iv)
            self.assertTrue(p["icv_ok"], comment)
            self.assertEqual(p["user_data"][:2], b"\x08\x00", comment)
            self.assertEqual(p["tag"].an, 3, comment)
            # Wrong salt (or wrong SSCI) -> different nonce -> ICV fails.
            bad = parse_frame(raw, keys.sak4, iv=xpn_iv(1, pn64, bytes(12)))
            self.assertFalse(bad["icv_ok"], comment)

    def test_xpn_frame_tamper_breaks_icv(self) -> None:
        keys = LabKeys.default()
        _, raw = next(
            (c, r) for c, r in mka_xpn(keys) if int.from_bytes(r[12:14], "big") == 0x88E5
        )
        pn64 = (XPN_INITIAL_PN64_HIGH << 32) | 0xFFFFFFFF
        iv = xpn_iv(assign_sscis([keys.a.sci, keys.b.sci])[keys.a.sci], pn64, xpn_default_salt(keys.a.sci))
        tampered = bytearray(raw)
        tampered[-1] ^= 0x01  # flip one ICV bit
        self.assertFalse(parse_frame(bytes(tampered), keys.sak4, keys.a.sci, iv=iv)["icv_ok"])

    def test_pn_tracker_wrap_vs_reorder(self) -> None:
        t = XpnPnTracker(high=1)
        self.assertEqual(t.update(0xFFFFFFFE), 0x1FFFFFFFE)
        self.assertEqual(t.update(0xFFFFFFFF), 0x1FFFFFFFF)
        # Big backwards jump = wrap: high half increments.
        self.assertEqual(t.update(0x00000001), 0x200000001)
        # Small backwards step = reordering, not a wrap.
        t2 = XpnPnTracker(high=2, last_low=0x00000100)
        self.assertEqual(t2.update(0x00000080), 0x200000080)
        with self.assertRaises(ValueError):
            XpnPnTracker().update(0)  # PN starts at 1
        with self.assertRaises(ValueError):
            XpnPnTracker(high=2**32)


if __name__ == "__main__":
    unittest.main()
