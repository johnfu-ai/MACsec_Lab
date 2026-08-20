"""IEEE 802.1AE GCM-AES and IEEE 802.1X AES-CMAC KDF / AES Key Wrap."""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

GCM_ICV_LEN = 16
MKA_ICV_LEN = 16


def aes_cmac(key: bytes, msg: bytes) -> bytes:
    c = CMAC(algorithms.AES(key))
    c.update(msg)
    return c.finalize()


def aes_kdf(kdk: bytes, label: str, context: bytes, ret_bits: int) -> bytes:
    """IEEE 802.1X-2020 6.2.1 / NIST SP 800-108 counter-mode KDF (r=8, h=128)."""
    if len(kdk) not in (16, 32):
        raise ValueError("KDK must be 128 or 256 bits")
    lab = label.encode("ascii")
    ret_len = (ret_bits + 7) // 8
    n = (ret_bits + 127) // 128
    out = bytearray()
    for i in range(1, n + 1):
        msg = bytes([i]) + lab + b"\x00" + context + ret_bits.to_bytes(2, "big")
        out += aes_cmac(kdk, msg)
    return bytes(out[:ret_len])


def derive_kek(cak: bytes, ckn: bytes, kek_len: int = 16) -> bytes:
    """KEK = KDF(CAK, 'IEEE8021 KEK', CKN[0:16], KEKlength)."""
    ctx = (ckn + bytes(16))[:16]
    return aes_kdf(cak, "IEEE8021 KEK", ctx, kek_len * 8)


def derive_ick(cak: bytes, ckn: bytes, ick_len: int = 16) -> bytes:
    """ICK = KDF(CAK, 'IEEE8021 ICK', CKN[0:16], ICKlength)."""
    ctx = (ckn + bytes(16))[:16]
    return aes_kdf(cak, "IEEE8021 ICK", ctx, ick_len * 8)


def ordered_macs(mac_a: bytes, mac_b: bytes) -> bytes:
    """802.1X 6.2.2: mac1 is the numerically lesser address, mac2 the greater."""
    if len(mac_a) != 6 or len(mac_b) != 6:
        raise ValueError("MAC addresses must be 6 octets")
    if mac_a < mac_b:
        return mac_a + mac_b
    return mac_b + mac_a


def derive_eap_cak(msk: bytes, mac_a: bytes, mac_b: bytes, cak_len: int = 16) -> bytes:
    """CAK = KDF(MSK[0:cak_len], 'IEEE8021 EAP CAK', mac1||mac2, CAKlength).

    Labels are 16 ASCII bytes (not the 12-byte KEK/ICK labels).
    """
    key = msk[:cak_len]
    return aes_kdf(key, "IEEE8021 EAP CAK", ordered_macs(mac_a, mac_b), cak_len * 8)


def derive_eap_ckn(msk: bytes, mac_a: bytes, mac_b: bytes, session_id: bytes, cak_len: int = 16) -> bytes:
    """CKN = KDF(MSK[0:cak_len], 'IEEE8021 EAP CKN', Session-ID||mac1||mac2, 128)."""
    key = msk[:cak_len]
    ctx = session_id + ordered_macs(mac_a, mac_b)
    return aes_kdf(key, "IEEE8021 EAP CKN", ctx, 128)


def wrap_sak(kek: bytes, sak: bytes) -> bytes:
    return aes_key_wrap(kek, sak)


def unwrap_sak(kek: bytes, wrapped: bytes) -> bytes:
    return aes_key_unwrap(kek, wrapped)


def gcm_protect(key: bytes, iv: bytes, aad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Return (ciphertext, 16-byte ICV). plaintext may be empty (integrity-only)."""
    if len(iv) != 12:
        raise ValueError("GCM IV must be 96 bits (SCI || PN)")
    blob = AESGCM(key).encrypt(iv, plaintext, aad)
    return blob[:-GCM_ICV_LEN], blob[-GCM_ICV_LEN:]


def gcm_validate(key: bytes, iv: bytes, aad: bytes, ciphertext: bytes, icv: bytes) -> bytes:
    """Return plaintext (empty for integrity-only). Raises on ICV failure."""
    return AESGCM(key).decrypt(iv, ciphertext + icv, aad)


def xpn_iv(ssci: int, pn64: int, salt: bytes) -> bytes:
    """802.1AEbw-2013 XPN nonce: IV = (SSCI(32) || PN(64)) XOR Salt(96).

    The SecTAG PN field still carries only the low 32 bits of pn64; the
    receiver recovers the high 32 bits from SA state (802.1AE 10.6).
    """
    if not 0 <= ssci <= 0xFFFFFFFF:
        raise ValueError("SSCI is 32 bits")
    if not 0 <= pn64 <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("PN is 64 bits in XPN")
    if len(salt) != 12:
        raise ValueError("XPN salt must be 96 bits")
    iv = ssci.to_bytes(4, "big") + pn64.to_bytes(8, "big")
    return bytes(a ^ b for a, b in zip(iv, salt))


def xpn_default_salt(ks_sci: bytes) -> bytes:
    """Default XPN salt derived from the Key Server SCI (802.1AEbw-2013):
    Salt[0:4] = SCI[0:4] XOR SCI[4:8], Salt[4:12] = the KS SCI itself.

    The salt is public material — it decorrelates the nonce from the default
    SCI||PN construction; it is not a second key.
    """
    if len(ks_sci) != 8:
        raise ValueError("SCI must be 64 bits")
    xor = bytes(a ^ b for a, b in zip(ks_sci[:4], ks_sci[4:]))
    return xor + ks_sci


def assign_sscis(scis: list[bytes]) -> dict[bytes, int]:
    """Default SSCI assignment (802.1AEbw-2013): order the SCIs by value,
    largest SCI gets SSCI 0x0001, next 0x0002, and so on.

    Deterministic on both sides, so peers agree without signaling.
    """
    out: dict[bytes, int] = {}
    for i, sci in enumerate(sorted(scis, reverse=True), 1):
        out[sci] = i
    return out
