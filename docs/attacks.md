# Attack surface (study notes)

Educational summary. Not a pentest guide.

| Risk | Why it matters | Mitigation in real deployments |
|---|---|---|
| CAK leak | Attacker can join the CA and unwrap SAK | HSM / secure storage; rotate CAK; least privilege |
| Wrong CKN/CAK pair | MKA never comes up; some gear fail-open to plaintext | Strict mode; monitor MKA session; check CKN on the wire |
| PN wrap / nonce reuse | GCM collapses if (SAK, IV) repeats | Roll SAK before PN exhaustion; replay window |
| Fail-open | MKA down still forwards user frames | Drop all but MKA/LLDP/PAUSE on confidential links |
| Capture point vs offload | NIC may decrypt before tcpdump | Know whether the tap is before or after SecY |
| Hop-by-hop only | MACsec stops at the next SecY | Combine with IPsec/TLS for end-to-end |

Lab keys in `captures/keys.json` are intentionally public.
