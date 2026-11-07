import json
from pathlib import Path

import pytest

from tba_core.b64 import b64url_decode
from tba_core.encoding import EncodingError, canonical_bytes, decode_qr_payload, encode_qr_payload
from tba_core.hmac_otp import tx_otp
from tba_core.signature import public_key_from_raw, verify_tx_signature
from tba_core.totp import totp

VECTORS = json.loads((Path(__file__).resolve().parents[2] / "shared" / "vectors.json").read_text())
HMAC_KEY = b64url_decode(VECTORS["hmac_key"])
TOTP_KEY = b64url_decode(VECTORS["totp_key"])
PUB = public_key_from_raw(b64url_decode(VECTORS["p256_public_key"]))


@pytest.mark.parametrize("case", VECTORS["transactions"])
def test_transaction_vectors(case):
    tx = case["tx"]
    assert canonical_bytes(tx).decode() == case["canonical"]
    assert encode_qr_payload(tx) == case["qr_payload"]
    assert decode_qr_payload(case["qr_payload"]) == tx
    assert tx_otp(HMAC_KEY, tx, 6) == case["hmac_otp_6"]
    assert tx_otp(HMAC_KEY, tx, 8) == case["hmac_otp_8"]
    assert verify_tx_signature(PUB, tx, b64url_decode(case["signature"]))


@pytest.mark.parametrize("case", VECTORS["totp"])
def test_totp_vectors(case):
    assert totp(TOTP_KEY, case["t"], digits=case["digits"]) == case["code"]


@pytest.mark.parametrize("case", VECTORS["invalid_qr_payloads"], ids=lambda c: c["name"])
def test_invalid_payloads_rejected(case):
    with pytest.raises(EncodingError):
        decode_qr_payload(case["payload"])


def test_has_all_invalid_cases():
    assert len(VECTORS["invalid_qr_payloads"]) == 14
