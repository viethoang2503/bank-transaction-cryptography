import re

from tba_core.challenge import new_tx
from tba_core.encoding import canonical_bytes, parse_canonical

from .db import audit, write_tx

_ACCOUNT = re.compile(r"[0-9]{6,20}")
_AMOUNT = re.compile(r"[0-9]{1,16}")


class TransferError(Exception):
    """User-facing validation error."""


def lookup_account(conn, account: str):
    if not isinstance(account, str) or not _ACCOUNT.fullmatch(account):
        return None
    return conn.execute("SELECT account, display_name FROM users WHERE account = ?", (account,)).fetchone()


def create_transfer(conn, settings, user, to: str, amount_text: str, now: int) -> dict:
    if not _ACCOUNT.fullmatch(to):
        raise TransferError("Invalid account number")
    if not _AMOUNT.fullmatch(amount_text) or int(amount_text) < 1:
        raise TransferError("Invalid amount")
    amount = int(amount_text)
    if to == user["account"]:
        raise TransferError("Cannot transfer to your own account")
    recipient = lookup_account(conn, to)
    if recipient is None:
        raise TransferError("Unknown recipient account")
    with write_tx(conn):
        if conn.execute("SELECT 1 FROM devices WHERE user_id = ?", (user["id"],)).fetchone() is None:
            raise TransferError("Enroll an authenticator first")
        balance = conn.execute("SELECT balance FROM users WHERE id = ?", (user["id"],)).fetchone()["balance"]
        if amount > balance:
            raise TransferError("Insufficient balance")
        tx = new_tx(user["account"], to, recipient["display_name"], amount, now=now, ttl=settings.tx_ttl)
        conn.execute(
            "INSERT INTO transactions (tx_id, user_id, mode, canonical, state, attempts, created_at) "
            "VALUES (?, ?, ?, ?, 'pending', 0, ?)",
            (tx["tx_id"], user["id"], settings.mode, canonical_bytes(tx), now),
        )
        audit(conn, now, user["id"], tx["tx_id"], "tx_created", f"to={to} amount={amount}")
    return tx


def get_tx_for_user(conn, tx_id: str, user_id: int) -> dict | None:
    row = conn.execute(
        "SELECT canonical FROM transactions WHERE tx_id = ? AND user_id = ?", (tx_id, user_id)
    ).fetchone()
    return parse_canonical(bytes(row["canonical"])) if row else None


def current_state(conn, tx_id: str, user_id: int, now: int) -> str | None:
    row = conn.execute(
        "SELECT state, canonical FROM transactions WHERE tx_id = ? AND user_id = ?", (tx_id, user_id)
    ).fetchone()
    if row is None:
        return None
    if row["state"] == "pending" and now > parse_canonical(bytes(row["canonical"]))["exp"]:
        conn.execute("UPDATE transactions SET state = 'expired' WHERE tx_id = ? AND state = 'pending'", (tx_id,))
        return "expired"
    return row["state"]
