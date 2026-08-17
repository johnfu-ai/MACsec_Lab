MACsec Lab — decoded learning artifacts
=======================================

01-mka-handshake.md                 Field-level MKA parse (ICV verified, SAK unwrapped)
02-macsec-encrypted.md              Lab GCM-AES-128 confidentiality frames
03-macsec-integrity-only.md         Same ICMP, E=0 C=0 so inner IPv4 is visible
04-ieee-integrity.md                Official IEEE GCM-AES-128 integrity vector
05-ieee-encrypt.md                  Official IEEE GCM-AES-128 confidentiality vector
06-session-full.md                  MKA then MACsec in one capture
07-tshark-session-summary.txt       One-line tshark list (if tshark installed)
08-tshark-mka-verbose.txt           Wireshark MKA tree
09-tshark-macsec-verbose.txt        Wireshark MACsec tree
10-tshark-ieee-encrypt-verbose.txt  Wireshark tree of the published encrypt vector
00-protocol-hierarchy.txt           tshark protocol hierarchy

Open the pcaps in Wireshark:
  captures/session-full.pcap
  Filter:  mka || macsec
