import pytest

from tba_core.signature import (
    P256_ORDER,
    generate_ed25519,
    generate_p256,
    public_key_from_raw,
    public_key_to_raw,
    raw_to_der,
    sign_tx,
    sign_tx_ed25519,
    verify_tx_signature,
    verify_tx_signature_ed25519,
)
from tests.core.test_encoding import TX


def test_sign_verify_raw_64_bytes():
    sk = generate_p256()
    sig = sign_tx(sk, TX)
    assert len(sig) == 64
    assert verify_tx_signature(sk.public_key(), TX, sig)


def test_public_key_raw_roundtrip():
    sk = generate_p256()
    raw = public_key_to_raw(sk.public_key())
    assert len(raw) == 65 and raw[0] == 0x04
    assert verify_tx_signature(public_key_from_raw(raw), TX, sign_tx(sk, TX))


def test_rejects_invalid_point():
    with pytest.raises(ValueError):
        public_key_from_raw(b"\x04" + b"\x01" * 64)


def test_signature_bound_to_transaction():
    sk = generate_p256()
    sig = sign_tx(sk, TX)
    assert not verify_tx_signature(sk.public_key(), dict(TX, to="0999888777"), sig)


def test_wrong_key_rejected():
    assert not verify_tx_signature(generate_p256().public_key(), TX, sign_tx(generate_p256(), TX))


def test_malformed_signatures_rejected_without_exception():
    sk = generate_p256()
    good = sign_tx(sk, TX)
    n = P256_ORDER.to_bytes(32, "big")
    for bad in [b"", bytes(64), good[:63], good + b"\x00", raw_to_der(good),
                n + good[32:], good[:32] + n, bytes(32) + good[32:], "not-bytes"]:
        assert not verify_tx_signature(sk.public_key(), TX, bad)


def test_ed25519():
    sk = generate_ed25519()
    sig = sign_tx_ed25519(sk, TX)
    assert len(sig) == 64
    assert verify_tx_signature_ed25519(sk.public_key(), TX, sig)
    assert not verify_tx_signature_ed25519(sk.public_key(), dict(TX, amount=1), sig)
