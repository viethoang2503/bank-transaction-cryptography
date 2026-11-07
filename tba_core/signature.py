"""Signature-bound confirmation. ECDSA P-256 is used by the phone (Web Crypto);
Ed25519 is only benchmarked.

Web Crypto produces raw r||s (IEEE P1363, 64 bytes); `cryptography` wants DER,
so we convert at this boundary.
"""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from .encoding import SIG_TAG, tagged_message

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_ECDSA = ec.ECDSA(hashes.SHA256())


def generate_p256() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def public_key_to_raw(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def public_key_from_raw(data: bytes) -> ec.EllipticCurvePublicKey:
    if not isinstance(data, bytes) or len(data) != 65 or data[0] != 0x04:
        raise ValueError("expected 65-byte uncompressed P-256 point")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)


def raw_to_der(signature: bytes) -> bytes:
    return encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))


def sign_tx(private_key: ec.EllipticCurvePrivateKey, tx: dict) -> bytes:
    r, s = decode_dss_signature(private_key.sign(tagged_message(SIG_TAG, tx), _ECDSA))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_tx_signature(public_key: ec.EllipticCurvePublicKey, tx: dict, signature: bytes) -> bool:
    if not isinstance(signature, bytes) or len(signature) != 64:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (0 < r < P256_ORDER and 0 < s < P256_ORDER):
        return False
    try:
        public_key.verify(encode_dss_signature(r, s), tagged_message(SIG_TAG, tx), _ECDSA)
        return True
    except InvalidSignature:
        return False


def generate_ed25519() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def sign_tx_ed25519(private_key: ed25519.Ed25519PrivateKey, tx: dict) -> bytes:
    return private_key.sign(tagged_message(SIG_TAG, tx))


def verify_tx_signature_ed25519(public_key: ed25519.Ed25519PublicKey, tx: dict, signature: bytes) -> bool:
    try:
        public_key.verify(signature, tagged_message(SIG_TAG, tx))
        return True
    except InvalidSignature:
        return False
