# MACsec Lab — Specification

## Purpose
Give a single-host (WSL2) study environment for IEEE 802.1AE MACsec and IEEE 802.1X MKA: reference PCAPs, field-level parsers, and cryptographically valid ICV/SAK wrap so Wireshark's `mka` / `macsec` dissectors accept the frames.

## Why not `ip macsec` / wpa_supplicant here
The current WSL2 kernel reports `# CONFIG_MACSEC is not set`. Docker containers share that kernel, so a strongSwan-style "real stack" lab cannot install SecY SAs. The lab therefore:

1. Implements GCM-AES-128 (802.1AE Clause 14) and MKA encoding (802.1X Clause 9/11) in Python.
2. Commits PCAPs that match IEEE published test vectors byte-for-byte on ICV.
3. Optionally replays those frames on a veth/bridge with AF_PACKET (`sudo make lab`) so a live tcpdump still exists.

## Scope
- PSK CAK (static CKN/CAK), point-to-point CA, GCM-AES-128
- MKA: Basic, Potential/Live Peer List, Distributed SAK, SAK Use, 16-octet ICV
- MACsec: SecTAG with and without explicit SCI, confidentiality and integrity-only
- Out of scope: EAP-derived CAK, GCM-AES-XPN, GCM-AES-256 data plane in the lab story (vectors for 256 exist in the IEEE PDF only), MKA announcements, VLAN-in-clear

## Deliverables
1. `captures/*.pcap` + `keys.json`
2. `macsec_lab` parsers and `captures/decoded/*.md`
3. Docs under `docs/`
4. `make test` / `make verify`

## Privileges
`make test` / `make generate` need no sudo. `make lab` needs root for netns, bridge, and raw sockets.
