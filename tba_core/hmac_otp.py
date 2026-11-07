"""Transaction-bound OTP: OCRA-style HMAC over the canonical transaction."""
import hashlib
import hmac
import re

from .encoding import HMAC_TAG, tagged_message
from .totp import dynamic_truncate

_DIGITS = re.compile(r"[0-9]+")


def tx_otp(key: bytes, tx: dict, digits: int = 8) -> str:
    mac = hmac.new(key, tagged_message(HMAC_TAG, tx), hashlib.sha256).digest()
    return dynamic_truncate(mac, digits)


def verify_tx_otp(key: bytes, tx: dict, code: str, digits: int = 8) -> bool:
    if not (isinstance(code, str) and len(code) == digits and code.isascii() and _DIGITS.fullmatch(code)):
        return False
    return hmac.compare_digest(tx_otp(key, tx, digits), code)
