# Standards map

| Topic | Spec | Lab mapping |
|---|---|---|
| SecTAG, SecY, PN, SCI | IEEE 802.1AE-2018 Clause 7–10 | `macsec_lab/macsec.py`, `docs/macsec-protocol-analysis.md` |
| GCM-AES-128 IV/AAD/ICV | IEEE 802.1AE-2018 Clause 14 | `macsec_lab/crypto.py` `gcm_protect` |
| Published GCM vectors | [Randall 2011](https://ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf) | `tests/test_protocol.py`, `captures/macsec-ieee-*.pcap` |
| MKA, KaY, MKPDU | IEEE 802.1X-2020 Clause 9, 11 | `macsec_lab/mka.py` |
| KDF, KEK, ICK | 802.1X 6.2.1, 9.3.3 | `derive_kek` / `derive_ick` |
| MKPDU ICV | 802.1X 9.4.1 | `mka_icv_input` |
| AES-CMAC | IETF RFC 4493 | `aes_cmac` |
| AES Key Wrap | IETF RFC 3394 / 802.1X 9.8.2 | `wrap_sak` |
| EAPOL type table | 802.1X Table 11-3 | Type 5 = EAPOL-MKA |
| YANG (management only) | RFC 9191 etc. | not in lab |

There is no IETF RFC that replaces 802.1AE. MACsec is IEEE; IPsec is IETF.
