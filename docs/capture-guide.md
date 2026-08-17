# Packet capture guide

## Already captured (no sudo)

```bash
make generate
tshark -r captures/session-full.pcap -nn
tshark -r captures/mka-handshake.pcap -Y mka -V | less
tshark -r captures/macsec-lab-encrypted.pcap -Y macsec -V | less
```

Display filters:

| Filter | Shows |
|---|---|
| `mka` | EAPOL-MKA |
| `macsec` | EtherType 0x88E5 |
| `eapol.type == 5` | MKA packet type |
| `eth.type == 0x88e5` | MACsec |
| `mka.key_server` | Key Server flag |
| `mka.cak_name` | CKN |
| `macsec.sl` | Short Length |

## Live replay

```bash
sudo make lab          # writes captures/live-session.pcap
sudo tcpdump -i br-macsec -nn 'ether proto 0x888e or ether proto 0x88e5'
```

## Manual decode without Wireshark

```bash
PYTHONPATH=. python3 -m macsec_lab analyze
# → captures/decoded/*.md  (ICV checked, SAK unwrapped, inner IPv4 shown)
```

## Windows Wireshark on WSL2 files

```
\\wsl$\Ubuntu\home\<you>\MACsec_Lab\captures\session-full.pcap
```
