# AGENTS.md — MACsec Lab

Guidance for agents and humans working in this repository.

## What this is

An educational IEEE 802.1AE + 802.1X MKA lab in the same family as `IPsec_Lab` and `IEEE_802.1X_Lab`. It ships **Wireshark-ready PCAPs**, a Python implementation of GCM-AES-128 / MKA, and field-level Markdown dumps.

The WSL2 kernel used when the lab was written has `# CONFIG_MACSEC is not set`. Do not add a Docker/`ip macsec` "real SecY" path unless you have verified `modinfo macsec` works on the target kernel.

## Commands

| Goal | Command |
|---|---|
| Tests (IEEE vectors must pass) | `make test` |
| Rebuild pcaps + decoded reports | `make generate` |
| tshark + tests | `make verify` |
| Live AF_PACKET replay | `sudo make lab` |

When asked "does it work?", run `make verify` and read the output.

## Invariants

1. **EAPOL-MKA type is 5**, not 6.
2. MACsec AAD includes EtherType `0x88E5` as part of the SecTAG.
3. GCM IV is always SCI(8) || PN(4), even when SCI is omitted on the wire (ES=1).
4. MKA ICV input is DA || SA || 0x888E || EAPOL without ICV (802.1X 9.4.1).
5. KDF labels are exactly 12 ASCII bytes: `IEEE8021 KEK`, `IEEE8021 ICK`.
6. Demo keys in `keys.py` / `captures/keys.json` stay demo keys. Do not "strengthen" them into looking like production secrets.
7. IEEE Randall vectors in `tests/test_protocol.py` are the crypto oracle. If a change breaks them, the change is wrong.
8. Mermaid / flowchart **message labels** are English: the `A->>B: ...` arrow text and `Note` lines. Surrounding Markdown prose may stay Chinese.
9. PSK CAK and EAP-derived CAK are different stories. MKPDU parameter sets (Basic / Peer List / Distributed SAK / SAK Use) are the same protocol; do not fold them into one pcap. The EAP path starts at **EAP-Success**, derives CAK/CKN from MSK (`IEEE8021 EAP CAK` / `IEEE8021 EAP CKN`, 16-byte labels), and the Authenticator is Key Server. Full EAP-TLS lives in `IEEE_802.1X_Lab`.

## Layout

- `macsec_lab/crypto.py` — GCM, AES-CMAC KDF, AES-KW, XPN nonce/salt/SSCI helpers
- `macsec_lab/macsec.py` — SecTAG, `XpnPnTracker` (64-bit PN recovery, 802.1AE 10.6), `ReplayWindow` (receive-side replay/delay-protect verdicts, Clause 10)
- `macsec_lab/mka.py` — MKPDU
- `macsec_lab/scenario.py` — PSK handshake, EAP-Success + MKA, SAK rekey, co30, XPN story, multi-peer CA, replay window, delay protect, ICMP frames
- `docs/key-hierarchy.md` — CAK / CKN / KEK / ICK / SAK (PSK vs EAP; SAK is not KDF from CAK)
- `docs/secy-processing.md` — SecY transmit/receive model, validate-frames modes, discard counters
- `docs/mka-reference.md` — identifiers, KS election, peer states, per-parameter-set field tables
- `docs/lifecycle.md` — rekey story (AN/KN rotation, PN exhaustion, SAK retire); capture `mka-rekey.pcap` needs `LabKeys.sak2`
- `docs/cipher-suites.md` — 128/256/XPN suites; capture `mka-xpn.pcap` needs `LabKeys.sak4` (MKA version 3, non-zero KS SSCI bytes)
- `docs/attacks.md` / `docs/faq.md` / `docs/glossary.md` / `docs/vs-ipsec.md` — knowledge-base layers (attack analysis, 36 FAQ, 80+ terms, four-protocol comparison)
- `captures/` — committed pcaps

### Story-key contract (which LabKeys field each capture needs)

| Capture | SAK | AN/KN | Notes |
|---|---|---|---|
| `mka-handshake.pcap` / `session-full.pcap` / `macsec-lab-*.pcap` / `macsec-replay.pcap` / `mka-delay-protect.pcap` / `mka-multi-peer.pcap` | `sak` | 0/1 | one CAK universe, MN 1-3 then per-story |
| `mka-rekey.pcap` | `sak` → `sak2` | 0/1 → 1/2 | needs `LabKeys.sak2` |
| `mka-co30.pcap` | `sak3` | 2/3 | co=30 signaled in Distributed SAK |
| `mka-xpn.pcap` | `sak4` | 3/4 | MKA version 3, XPN suite ID, SSCI/salt |
