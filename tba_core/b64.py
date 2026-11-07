"""Strict base64url without padding."""
import base64
import re

_ALPHABET = re.compile(r"[A-Za-z0-9_-]*")


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    if not isinstance(s, str) or not _ALPHABET.fullmatch(s) or len(s) % 4 == 1:
        raise ValueError("invalid base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
