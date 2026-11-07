"""HOTP (RFC 4226) and TOTP (RFC 6238). This is the unbound baseline."""
import hashlib
import hmac
import re
import struct

_DIGITS = re.compile(r"[0-9]+")


def dynamic_truncate(mac: bytes, digits: int) -> str:
    if not 3 <= digits <= 9:
        raise ValueError("digits must be between 3 and 9")
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10**digits).zfill(digits)


def hotp(key: bytes, counter: int, digits: int = 6, algorithm: str = "sha1") -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), getattr(hashlib, algorithm)).digest()
    return dynamic_truncate(mac, digits)


def totp(key: bytes, unix_time: int, digits: int = 6, step: int = 30) -> str:
    return hotp(key, unix_time // step, digits)


def _well_formed(code, digits: int) -> bool:
    return isinstance(code, str) and len(code) == digits and code.isascii() and bool(_DIGITS.fullmatch(code))


def totp_verify(key: bytes, code: str, unix_time: int, last_used_step: int | None,
                digits: int = 6, window: int = 1, step: int = 30) -> int | None:
    if not _well_formed(code, digits):
        return None
    current = unix_time // step
    for candidate in range(current - window, current + window + 1):
        if candidate < 0 or (last_used_step is not None and candidate <= last_used_step):
            continue
        if hmac.compare_digest(hotp(key, candidate, digits), code):
            return candidate
    return None
