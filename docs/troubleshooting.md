# Troubleshooting

## `make test` fails on IEEE vectors

`cryptography` must provide AES-GCM identical to NIST SP 800-38D. Use `python3 -m pip install -r requirements.txt`. Do not change TCI/SL/PN/SCI in `keys.py` IEEE constants.

## tshark shows MACsec `[UNVERIFIED]`

Expected until Wireshark is given the SAK. Either:

- Preferences → Protocols → MKA → CKN + CAK from `captures/keys.json` (then Wireshark can unwrap SAK from the MKA capture), or
- Trust `captures/decoded/*.md` (`ICV valid = True` from this repo's parser).

## tshark does not show `mka`

Need Wireshark/tshark recent enough to include `packet-mka.c` (the lab was checked with tshark 4.6). Filter `eapol.type == 5` still works.

## `sudo make lab` captures no MKA

Linux bridge drops PAE group DA `01:80:c2:00:00:03` unless:

```bash
echo 8 | sudo tee /sys/class/net/br-macsec/bridge/group_fwd_mask
```

The lab script already writes this. If you recreated the bridge by hand, set it again.

## Host has no `CONFIG_MACSEC`

Normal on this WSL2 kernel. Do not expect `ip link add type macsec` to create a working SecY. Reference PCAPs do not need the module.

## Inner IPv4 not visible in encrypted pcap

Use `macsec-lab-integrity-only.pcap` (E=0 C=0) or run `python3 -m macsec_lab analyze` which decrypts with the lab SAK.
