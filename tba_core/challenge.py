"""Fresh transactions: 128-bit nonce, random tx_id, short expiry."""
import secrets
import uuid

from .b64 import b64url_encode
from .encoding import validate_tx

NONCE_BYTES = 16
TTL_SECONDS = 120


def new_nonce() -> str:
    return b64url_encode(secrets.token_bytes(NONCE_BYTES))


def new_tx(from_account: str, to_account: str, to_name: str, amount: int, *,
           now: int, currency: str = "VND", ttl: int = TTL_SECONDS) -> dict:
    tx = {
        "v": 1,
        "tx_id": str(uuid.uuid4()),
        "from": from_account,
        "to": to_account,
        "to_name": to_name,
        "amount": amount,
        "currency": currency,
        "nonce": new_nonce(),
        "exp": now + ttl,
    }
    validate_tx(tx)
    return tx


def is_expired(tx: dict, now: int) -> bool:
    return now > tx["exp"]
