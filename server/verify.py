"""Confirmation of pending transactions.

Every confirmation runs inside one BEGIN IMMEDIATE transaction, so two
concurrent requests can never both observe state='pending' (scenario S8).
The transaction is always rebuilt from the server's own canonical copy.
"""
from enum import Enum
from typing import Callable

from tba_core.encoding import parse_canonical
from tba_core.hmac_otp import verify_tx_otp
from tba_core.signature import public_key_from_raw, verify_tx_signature
from tba_core.totp import totp_verify

from .db import audit, write_tx

SIG_MODES = ("sig", "sig_blind")


class Result(str, Enum):
    OK = "ok"
    REJECTED = "rejected"


Check = Callable[[dict, object], bytes | None]  # (tx, device_row) -> evidence or None


def _execute_transfer(conn, tx: dict) -> bool:
    debited = conn.execute(
        "UPDATE users SET balance = balance - ? WHERE account = ? AND balance >= ?",
        (tx["amount"], tx["from"], tx["amount"]),
    )
    if debited.rowcount != 1:
        return False
    credited = conn.execute("UPDATE users SET balance = balance + ? WHERE account = ?", (tx["amount"], tx["to"]))
    if credited.rowcount != 1:
        raise RuntimeError("recipient vanished")  # rolls back the debit
    return True


def _confirm(conn, settings, user_id: int, tx_id: str, now: int, check: Check) -> Result:
    with write_tx(conn):
        row = conn.execute("SELECT * FROM transactions WHERE tx_id = ?", (tx_id,)).fetchone()
        if row is None or row["user_id"] != user_id:
            audit(conn, now, user_id, tx_id, "confirm_rejected", "unknown transaction")
            return Result.REJECTED
        if row["state"] != "pending":
            audit(conn, now, user_id, tx_id, "confirm_rejected", f"state={row['state']}")
            return Result.REJECTED
        tx = parse_canonical(bytes(row["canonical"]))
        if now > tx["exp"]:
            conn.execute("UPDATE transactions SET state = 'expired' WHERE tx_id = ?", (tx_id,))
            audit(conn, now, user_id, tx_id, "confirm_rejected", "expired")
            return Result.REJECTED
        device = conn.execute("SELECT * FROM devices WHERE user_id = ?", (user_id,)).fetchone()
        evidence = check(tx, device) if device is not None else None
        if evidence is None:
            attempts = row["attempts"] + 1
            new_state = "failed" if attempts >= settings.max_attempts else "pending"
            conn.execute("UPDATE transactions SET attempts = ?, state = ? WHERE tx_id = ?", (attempts, new_state, tx_id))
            audit(conn, now, user_id, tx_id, "confirm_failed", f"attempt {attempts}, state={new_state}")
            return Result.REJECTED
        if not _execute_transfer(conn, tx):
            conn.execute("UPDATE transactions SET state = 'failed' WHERE tx_id = ?", (tx_id,))
            audit(conn, now, user_id, tx_id, "confirm_rejected", "insufficient funds")
            return Result.REJECTED
        conn.execute(
            "UPDATE transactions SET state = 'executed', evidence = ? WHERE tx_id = ? AND state = 'pending'",
            (evidence, tx_id),
        )
        audit(conn, now, user_id, tx_id, "executed", settings.mode)
        return Result.OK


def _wrong_mode(conn, user_id, tx_id: str, now: int) -> Result:
    # Evidence of the wrong kind is refused without spending one of the
    # transaction's attempts, so it cannot be used to lock a transaction out.
    audit(conn, now, user_id, tx_id, "confirm_rejected", "wrong evidence type for mode")
    return Result.REJECTED


def confirm_otp(conn, settings, user_id: int, tx_id: str, code: str, now: int) -> Result:
    if settings.mode in SIG_MODES:
        return _wrong_mode(conn, user_id, tx_id, now)

    def check(tx, device):
        if settings.mode == "baseline":
            step = totp_verify(bytes(device["k_totp"]), code, now, device["last_totp_step"], digits=settings.totp_digits)
            if step is None:
                return None
            conn.execute("UPDATE devices SET last_totp_step = ? WHERE id = ?", (step, device["id"]))
            return code.encode("ascii")
        if settings.mode == "hmac" and verify_tx_otp(bytes(device["k_hmac"]), tx, code, settings.otp_digits):
            return code.encode("ascii")
        return None

    return _confirm(conn, settings, user_id, tx_id, now, check)


def confirm_signature(conn, settings, device_id: str, tx_id: str, signature: bytes, now: int) -> Result:
    owner = conn.execute("SELECT user_id FROM devices WHERE id = ?", (device_id,)).fetchone()
    if owner is None:
        audit(conn, now, None, tx_id, "confirm_rejected", "unknown device")
        return Result.REJECTED
    if settings.mode not in SIG_MODES:
        return _wrong_mode(conn, owner["user_id"], tx_id, now)

    def check(tx, device):
        if device["id"] != device_id:
            return None
        public_key = public_key_from_raw(bytes(device["public_key"]))
        return signature if verify_tx_signature(public_key, tx, signature) else None

    return _confirm(conn, settings, owner["user_id"], tx_id, now, check)
