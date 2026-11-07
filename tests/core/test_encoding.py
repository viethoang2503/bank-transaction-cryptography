import json

import pytest

from tba_core.b64 import b64url_encode
from tba_core.encoding import (
    HMAC_TAG,
    EncodingError,
    canonical_bytes,
    decode_qr_payload,
    encode_qr_payload,
    parse_canonical,
    tagged_message,
)

TX = {
    "v": 1,
    "tx_id": "3f2b8c1e-5a4d-4e7f-9b6a-1c2d3e4f5a6b",
    "from": "0011223344",
    "to": "0123456789",
    "to_name": "TRAN THI B",
    "amount": 1000000,
    "currency": "VND",
    "nonce": "AAECAwQFBgcICQoLDA0ODw",
    "exp": 1800000120,
}

EXPECTED = (
    b'{"amount":1000000,"currency":"VND","exp":1800000120,"from":"0011223344",'
    b'"nonce":"AAECAwQFBgcICQoLDA0ODw","to":"0123456789","to_name":"TRAN THI B",'
    b'"tx_id":"3f2b8c1e-5a4d-4e7f-9b6a-1c2d3e4f5a6b","v":1}'
)


def test_canonical_is_sorted_compact_ascii():
    assert canonical_bytes(TX) == EXPECTED


def test_parse_roundtrip():
    assert parse_canonical(EXPECTED) == TX


def test_tagged_message():
    assert tagged_message(HMAC_TAG, TX) == b"TBA-HMAC-v1\x00" + EXPECTED


def test_qr_roundtrip():
    payload = encode_qr_payload(TX)
    assert payload.startswith("tba1:")
    assert decode_qr_payload(payload) == TX


@pytest.mark.parametrize(
    "field,value",
    [
        ("amount", 0),
        ("amount", -5),
        ("amount", 2**53),
        ("amount", True),
        ("amount", 1.5),
        ("exp", "1800000120"),
        ("v", 2),
        ("to", "12345"),
        ("to", "01234567a9"),
        ("to_name", "Tran Thi B"),
        ("to_name", "TRÀN THI B"),
        ("nonce", "short"),
        ("currency", "vnd"),
        ("tx_id", "3F2B8C1E-5A4D-4E7F-9B6A-1C2D3E4F5A6B"),
        ("to", "0123456789\n"),
    ],
)
def test_validate_rejects_bad_fields(field, value):
    bad = dict(TX, **{field: value})
    with pytest.raises(EncodingError):
        canonical_bytes(bad)


def test_rejects_extra_and_missing_fields():
    with pytest.raises(EncodingError):
        canonical_bytes(dict(TX, extra=1))
    missing = dict(TX)
    del missing["nonce"]
    with pytest.raises(EncodingError):
        canonical_bytes(missing)


@pytest.mark.parametrize(
    "data",
    [
        json.dumps(TX, sort_keys=True).encode(),  # whitespace
        json.dumps(TX, separators=(",", ":")).encode(),  # unsorted keys
        EXPECTED.replace(b'"amount":1000000', b'"amount":1000000.0'),
        EXPECTED.replace(b'{"amount":1000000', b'{"amount":1,"amount":1000000'),
        EXPECTED.replace(b"TRAN THI B", "TRÀN THI B".encode("utf-8")),
        EXPECTED + b"\n",
        EXPECTED.replace(b'"amount":1000000', b'"amount":NaN'),
    ],
)
def test_parse_rejects_non_canonical(data):
    with pytest.raises(EncodingError):
        parse_canonical(data)


@pytest.mark.parametrize("payload", ["", "tba2:abc", "tba1:!!!!", b64url_encode(EXPECTED)])
def test_decode_qr_rejects_bad_payloads(payload):
    with pytest.raises(EncodingError):
        decode_qr_payload(payload)
