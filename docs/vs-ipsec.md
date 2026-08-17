# MACsec vs IPsec (for readers of IPsec_Lab)

| | This lab (MACsec) | IPsec_Lab |
|---|---|---|
| Layer | Ethernet | IP |
| Control | MKA (EAPOL type 5) | IKEv2 (UDP 500/4500) |
| Data | EtherType 0x88E5 + SecTAG | ESP (IP proto 50) |
| Channel id | SCI | SPI |
| Sequence | PN in SecTAG | ESP Sequence Number |
| Auth of control | AES-CMAC(ICK) | IKE AUTH / ECDSA certs |
| Scope | Single hop | End-to-end or tunnel across routers |
| Typical use | Switch/router port to port | Site-to-site, host VPN |

They stack: a packet can be MACsec-protected on a metro Ethernet hop and IPsec-protected across the WAN. MTU shrinks twice.
