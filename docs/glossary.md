# Glossary

| Term | Meaning |
|---|---|
| **CA** | Connectivity Association: participants sharing a CAK |
| **CAK / CKN** | Root key / its name. Never encrypts user frames |
| **KEK** | Key Encrypting Key, wraps SAK in MKA |
| **ICK** | ICV Key, only for MKPDU AES-CMAC |
| **SAK** | Secure Association Key, GCM key for user frames |
| **SA / AN** | Secure Association / 2-bit Association Number (0–3) |
| **SC / SCI** | Unidirectional Secure Channel / 8-octet identifier (MAC + Port ID) |
| **SecY** | MAC Security Entity (data plane) |
| **KaY** | Key Agreement Entity (MKA state machine) |
| **SecTAG** | `0x88E5` + TCI/AN + SL + PN + optional SCI |
| **PN** | Packet Number, GCM nonce half, replay protection |
| **MKPDU** | MKA protocol data unit inside EAPOL type 5 |
| **MI / MN** | 12-octet Member Identifier / Message Number |
| **Key Server** | Elected participant that generates and distributes SAK |
| **ICV** | Integrity Check Value (GCM tag on MACsec, AES-CMAC on MKA) |
