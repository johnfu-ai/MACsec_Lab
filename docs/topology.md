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

Same CAK/CKN on both sides. A wins Key Server (smaller priority). A wraps SAK with KEK and sends Distributed SAK. Data frames use that SAK.

## Live replay (`sudo make lab`)

```
  netns macsec-a ---- veth-a-br --+
                                  |  br-macsec   tcpdump  ether proto 0x888e or 0x88e5
  netns macsec-b ---- veth-b-br --+
```

`group_fwd_mask=8` on the bridge is required or Linux drops EAPOL destined to `01:80:c2:00:00:03` (same lesson as IEEE_802.1X_Lab).
