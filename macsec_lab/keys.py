"""Published lab identities and IEEE 802.1AE test-vector constants.

All keys in this file are DEMO material. Treat them as public the moment
this repository is cloned. Do not reuse them on any real network.
"""

from __future__ import annotations

from dataclasses import dataclass

from .crypto import derive_ick, derive_kek

PAE_GROUP_ADDR = bytes.fromhex("0180c2000003")
ETHERTYPE_EAPOL = 0x888E
ETHERTYPE_MACSEC = 0x88E5
ETHERTYPE_IPV4 = 0x0800

# IEEE 802.1X Table 11-3
EAPOL_TYPE_MKA = 5
EAPOL_VERSION = 3

MKA_ALGO_AGILITY = bytes.fromhex("0080c201")  # 00-80-C2-01 (802.1X-2010)

# IEEE 802.1AE GCM-AES-128 cipher suite ID (802.1AE Table 14-1)
CS_GCM_AES_128 = bytes.fromhex("0080c20001000001")


def _h(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", "").replace(":", ""))


# IEEE 802.1AE / Randall GCM-AES test vectors (bn-randall-test-vectors-0511)
IEEE_GCM_KEY_128 = _h("AD7A2BD03EAC835A6F620FDCB506B345")
IEEE_GCM_KEY_256 = _h(
    "E3C08A8F06C6E3AD95A70557B23F7548 3CE33021A9C72B7025666204C69C0B72"
)
IEEE_DA = _h("D609B1F05663")
IEEE_SA = _h("7A0D46DF998D")
IEEE_SCI = _h("12153524C0895E81")
IEEE_PN = 0xB2C28465

# 54-byte integrity-only (TCI/AN=0x22, SL=0x2A, SC=1, E=0, C=0, AN=2)
IEEE_INT_USER = _h(
    "08000F101112131415161718191A1B1C"
    "1D1E1F202122232425262728292A2B2C"
    "2D2E2F30313233340001"
)
IEEE_INT_ICV_128 = _h("F09478A9B09007D06F46E9B6A1DA25DD")

# 60-byte confidentiality (TCI/AN=0x2E, SL=0, SC=1, E=1, C=1, AN=2)
IEEE_ENC_USER = _h(
    "08000F101112131415161718191A1B1C"
    "1D1E1F202122232425262728292A2B2C"
    "2D2E2F303132333435363738393A0002"
)
IEEE_ENC_CT_128 = _h(
    "701AFA1CC039C0D765128A665DAB6924"
    "3899BF7318CCDC81C9931DA17FBE8EDD"
    "7D17CB8B4C26FC81E3284F2B7FBA713D"
)
IEEE_ENC_ICV_128 = _h("4F8D55E7D3F06FD5A13C0C29B9D5B880")


@dataclass(frozen=True)
class Peer:
    name: str
    mac: bytes
    port_id: int
    ks_priority: int
    mi: bytes
    sci: bytes

    @classmethod
    def make(cls, name: str, mac: bytes, port_id: int, ks_priority: int, mi: bytes) -> "Peer":
        sci = mac + port_id.to_bytes(2, "big")
        return cls(name, mac, port_id, ks_priority, mi, sci)


@dataclass(frozen=True)
class LabKeys:
    cak: bytes
    ckn: bytes
    sak: bytes
    kek: bytes
    ick: bytes
    kn: int
    an: int
    a: Peer
    b: Peer

    @classmethod
    def default(cls) -> "LabKeys":
        cak = _h("00112233445566778899aabbccddeeff")
        ckn = b"MACSEC-LAB-CKN01"  # 16 octets
        sak = _h("a1a2a3a4a5a6a7a8a9aaabacadaeafb0")
        a = Peer.make(
            "node-a",
            _h("02000000000a"),
            1,
            16,
            _h("aa01aa02aa03aa04aa05aa06"),
        )
        b = Peer.make(
            "node-b",
            _h("02000000000b"),
            1,
            32,
            _h("bb01bb02bb03bb04bb05bb06"),
        )
        return cls(
            cak=cak,
            ckn=ckn,
            sak=sak,
            kek=derive_kek(cak, ckn),
            ick=derive_ick(cak, ckn),
            kn=1,
            an=0,
            a=a,
            b=b,
        )

    def as_dict(self) -> dict[str, str]:
        return {
            "cak": self.cak.hex(),
            "ckn": self.ckn.hex(),
            "ckn_ascii": self.ckn.decode("ascii"),
            "sak": self.sak.hex(),
            "kek": self.kek.hex(),
            "ick": self.ick.hex(),
            "kn": f"{self.kn}",
            "an": f"{self.an}",
            "a_mac": self.a.mac.hex(":"),
            "a_sci": self.a.sci.hex(),
            "a_mi": self.a.mi.hex(),
            "a_ks_priority": str(self.a.ks_priority),
            "b_mac": self.b.mac.hex(":"),
            "b_sci": self.b.sci.hex(),
            "b_mi": self.b.mi.hex(),
            "b_ks_priority": str(self.b.ks_priority),
            "pae_group": PAE_GROUP_ADDR.hex(":"),
        }
