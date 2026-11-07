"""Generate shared/vectors.json. Run once and commit the output.

ECDSA signatures are randomized, so regenerating changes the "signature"
fields; tests only verify them, so any regenerated file is valid.
"""
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from tba_core.b64 import b64url_encode
from tba_core.encoding import canonical_bytes, encode_qr_payload
from tba_core.hmac_otp import tx_otp
from tba_core.signature import P256_ORDER, public_key_to_raw, sign_tx

OUT = Path(__file__).resolve().parents[1] / "shared" / "vectors.json"
HMAC_KEY = bytes(range(32))
TOTP_KEY = b"12345678901234567890"
_d = int.from_bytes(hashlib.sha256(b"tba-test-vector-key").digest(), "big") % (P256_ORDER - 1) + 1
SIGNING_KEY = ec.derive_private_key(_d, ec.SECP256R1())

TXS = [
    {"v": 1, "tx_id": "3f2b8c1e-5a4d-4e7f-9b6a-1c2d3e4f5a6b", "from": "0011223344",
     "to": "0123456789", "to_name": "TRAN THI B", "amount": 1000000, "currency": "VND",
     "nonce": b64url_encode(bytes(range(16))), "exp": 1800000120},
    {"v": 1, "tx_id": "a1b2c3d4-0000-4000-8000-000000000001", "from": "0011223344",
     "to": "0999888777", "to_name": "LE VAN M", "amount": 9000000, "currency": "VND",
     "nonce": b64url_encode(bytes(range(240, 256))), "exp": 1800000300},
    {"v": 1, "tx_id": "a1b2c3d4-0000-4000-8000-000000000002", "from": "0123456789",
     "to": "0011223344", "to_name": "NGUYEN VAN A", "amount": 2**53 - 1, "currency": "VND",
     "nonce": b64url_encode(b"\xff" * 16), "exp": 2**53 - 1},
]

TOTP = [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
        (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]


def _p(text) -> str:
    data = text.encode("utf-8") if isinstance(text, str) else text
    return "tba1:" + b64url_encode(data)


def invalid_payloads() -> list[dict]:
    base = TXS[0]
    canon = canonical_bytes(base).decode()
    missing = {k: v for k, v in base.items() if k != "nonce"}
    cases = [
        ("whitespace", _p(json.dumps(base, sort_keys=True))),
        ("unsorted_keys", _p(json.dumps(base, separators=(",", ":")))),
        ("float_amount", _p(canon.replace('"amount":1000000', '"amount":1000000.0'))),
        ("duplicate_key", _p(canon.replace('{"amount":1000000', '{"amount":1,"amount":1000000'))),
        ("nfd_name_utf8", _p(canon.replace('"TRAN THI B"', '"TRA\u0300N THI B"'))),
        ("escaped_unicode_name", _p(canon.replace('"TRAN THI B"', '"TR\\u00c0N THI B"'))),
        ("extra_field", _p(canon[:-1] + ',"zz":1}')),
        ("missing_field", _p(json.dumps(missing, sort_keys=True, separators=(",", ":")))),
        ("bool_amount", _p(canon.replace('"amount":1000000', '"amount":true'))),
        ("negative_amount", _p(canon.replace('"amount":1000000', '"amount":-1000000'))),
        ("too_large_amount", _p(canon.replace('"amount":1000000', '"amount":9007199254740993'))),
        ("no_prefix", b64url_encode(canon.encode())),
        ("bad_base64", "tba1:!!!!"),
        ("trailing_newline", _p(canon + "\n")),
    ]
    return [{"name": n, "payload": p} for n, p in cases]


def main() -> None:
    vectors = {
        "hmac_key": b64url_encode(HMAC_KEY),
        "totp_key": b64url_encode(TOTP_KEY),
        "p256_public_key": b64url_encode(public_key_to_raw(SIGNING_KEY.public_key())),
        "transactions": [
            {
                "tx": tx,
                "canonical": canonical_bytes(tx).decode(),
                "qr_payload": encode_qr_payload(tx),
                "hmac_otp_6": tx_otp(HMAC_KEY, tx, 6),
                "hmac_otp_8": tx_otp(HMAC_KEY, tx, 8),
                "signature": b64url_encode(sign_tx(SIGNING_KEY, tx)),
            }
            for tx in TXS
        ],
        "totp": [{"t": t, "digits": 8, "code": c} for t, c in TOTP],
        "invalid_qr_payloads": invalid_payloads(),
    }
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(vectors, indent=2) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
