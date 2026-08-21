# Topology

## Logical (what the pcaps simulate)

```
  node-a (Key Server)                 node-b
  MAC 02:00:00:00:00:0a               MAC 02:00:00:00:00:0b
  SCI  02:00:00:00:00:0a:00:01        SCI  02:00:00:00:00:0b:00:01
  KS priority 16                      KS priority 32
  10.10.0.10/24                       10.10.0.20/24
           \                             /
            \   PAE group 01:80:c2:00:00:03
             \         (MKA)            /
              +---------- LAN ----------+
                       MACsec 0x88E5
```

Same CAK/CKN on both sides (PSK). A wins Key Server (smaller priority). A wraps SAK with KEK and sends Distributed SAK. Data frames use that SAK.

## After 802.1X supplicant success (EAP-derived CAK)

```
  Authenticator (Key Server)          Supplicant
  MAC 02:00:00:00:00:0a               MAC 02:00:00:00:00:0b
  KS priority 0                       KS priority 255
           \                             /
            \   EAP-Success (unicast)
             \  then MKA to 01:80:c2:00:00:03
              +---------- LAN ----------+
```

CAK/CKN come from the EAP MSK (see `keys.json` → `eap`). MKPDUs after EAP-Success use the same parameter sets as the PSK handshake. Full EAP-TLS is in IEEE_802.1X_Lab.

## Multi-member CA (`mka-multi-peer.pcap`)

A CA is **group-keyed, not a pair**: every port configured with the same CAK/CKN joins the same CA. Three members, one Key Server, **one** SAK for everyone, three unidirectional SCs:

```
        node-a (Key Server, prio 16)          10.10.0.10
       /            \
   node-b (32)     node-c (48)               10.10.0.20 / .30

  A distributes SAK#1 once (group-keyed)
  A→B, B→C, C→A each transmit on their own SC (own SCI, own PN space)
  every data frame carries explicit SCI (SC=1) — the ES=1 no-SCI
  shortcut is only valid for a two-member CA
```

Per-frame decode: [captures/decoded/18-mka-multi-peer.md](../captures/decoded/18-mka-multi-peer.md). Key takeaways: the receiver instantiates one RX SA per remote member, keyed by (SCI, AN); three frames with PN=1 coexist without being a replay (different SCs).

## Live replay (`sudo make lab`)

```
  netns macsec-a ---- veth-a-br --+
                                  |  br-macsec   tcpdump  ether proto 0x888e or 0x88e5
  netns macsec-b ---- veth-b-br --+
```

`group_fwd_mask=8` on the bridge is required or Linux drops EAPOL destined to `01:80:c2:00:00:03` (same lesson as IEEE_802.1X_Lab).
