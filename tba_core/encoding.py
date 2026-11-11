"""Canonical transaction encoding shared by server, phone and evaluation.

The same rules are implemented in authenticator/js/canonical.js and are
cross-checked through shared/vectors.json.
"""
import json
import re

from .b64 import b64url_decode, b64url_encode

FIELDS = ("amount", "currency", "exp", "from", "nonce", "to", "to_name", "tx_id", "v")
MAX_INT = 2**53 - 1
HMAC_TAG = b"TBA-HMAC-v1"
SIG_TAG = b"TBA-SIG-v1"
QR_PREFIX = "tba1:"

_PATTERNS = {
    "from": re.compile(r"[0-9]{6,20}"),
    "to": re.compile(r"[0-9]{6,20}"),
    "to_name": re.compile(r"[A-Z0-9 ]{1,64}"),
    "nonce": re.compile(r"[A-Za-z0-9_-]{22}"),
    "tx_id": re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    "currency": re.compile(r"[A-Z]{3}"),
}


class EncodingError(ValueError):
    """Raised when a transaction or payload is not in canonical form."""


def _is_int(value) -> bool:
    return type(value) is int  # rejects bool, which is a subclass of int


def validate_tx(tx: dict) -> None:
    if not isinstance(tx, dict):
        raise EncodingError("transaction must be an object")
    if set(tx) != set(FIELDS):
        raise EncodingError("transaction fields mismatch")
    if not _is_int(tx["v"]) or tx["v"] != 1:
        raise EncodingError("unsupported version")
    for key in ("amount", "exp"):
        if not _is_int(tx[key]) or not 1 <= tx[key] <= MAX_INT:
            raise EncodingError(f"invalid {key}")
    for key, pattern in _PATTERNS.items():
        value = tx[key]
        if not isinstance(value, str) or not pattern.fullmatch(value):
            raise EncodingError(f"invalid {key}")


def canonical_bytes(tx: dict) -> bytes:
    validate_tx(tx)
    return json.dumps(tx, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _reject_float(text):
    raise EncodingError("floating point numbers are not allowed")


def _reject_constant(text):
    raise EncodingError("NaN/Infinity are not allowed")


def _no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise EncodingError("duplicate key")
    return dict(pairs)


def parse_canonical(data: bytes) -> dict:
    try:
        text = bytes(data).decode("ascii")
        obj = json.loads(
            text,
            object_pairs_hook=_no_duplicates,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except EncodingError:
        raise
    except (ValueError, TypeError, RecursionError) as exc:  # ValueError also covers over-long integers
        raise EncodingError("payload is not valid ASCII JSON") from exc
    if canonical_bytes(obj) != bytes(data):
        raise EncodingError("payload is not canonical")
    return obj


def tagged_message(tag: bytes, tx: dict) -> bytes:
    return tag + b"\x00" + canonical_bytes(tx)


def encode_qr_payload(tx: dict) -> str:
    return QR_PREFIX + b64url_encode(canonical_bytes(tx))


def decode_qr_payload(payload: str) -> dict:
    if not isinstance(payload, str) or not payload.startswith(QR_PREFIX):
        raise EncodingError("not a TBA transaction payload")
    try:
        data = b64url_decode(payload[len(QR_PREFIX):])
    except ValueError as exc:
        raise EncodingError("invalid base64url") from exc
    return parse_canonical(data)
