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
from macsec_lab.macsec import SecTAG, parse_frame, protect_frame
from macsec_lab.dissect import dissect_eap, dissect_macsec, dissect_mka
from macsec_lab.mka import parse_eapol_mka
from macsec_lab.scenario import (
    ieee_encrypt_frame,
    ieee_integrity_frame,
    macsec_lab_data,
    mka_after_eap,
    mka_handshake,
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
