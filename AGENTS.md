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

## Layout

- `macsec_lab/crypto.py` — GCM, AES-CMAC KDF, AES-KW
- `macsec_lab/macsec.py` — SecTAG
- `macsec_lab/mka.py` — MKPDU
- `macsec_lab/scenario.py` — handshake + ICMP frames
- `captures/` — committed pcaps
