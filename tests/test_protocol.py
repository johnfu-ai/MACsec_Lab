"""IEEE 802.1AE GCM-AES-128 published test vectors + lab round-trip."""

from __future__ import annotations

import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from macsec_lab.crypto import derive_eap_cak, derive_eap_ckn
from macsec_lab.keys import (
    EAPOL_TYPE_EAP,
    IEEE_DA,
    IEEE_ENC_CT_128,
    IEEE_ENC_ICV_128,
    IEEE_ENC_USER,
    IEEE_GCM_KEY_128,
    IEEE_INT_ICV_128,
    IEEE_INT_USER,
    IEEE_PN,
    IEEE_SA,
    IEEE_SCI,
    LabKeys,
)
from macsec_lab.l3 import ipv4_icmp_echo
from macsec_lab.macsec import SecTAG, parse_frame, protect_frame
from macsec_lab.dissect import dissect_eap, dissect_macsec, dissect_mka
from macsec_lab.mka import parse_eapol_mka
from macsec_lab.scenario import (
    ieee_encrypt_frame,
    ieee_integrity_frame,
    macsec_lab_data,
    mka_after_eap,
    mka_co30,
    mka_handshake,
    mka_rekey,
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


if __name__ == "__main__":
    unittest.main()
