import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass

from .db import audit, write_tx

_SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}


@dataclass(frozen=True)
class DemoUser:
    username: str
    password: str
    account: str
    name: str
    balance: int


DEMO_USERS = (
    DemoUser("alice", "alice-pass", "0011223344", "NGUYEN VAN A", 100_000_000),
    DemoUser("bob", "bob-pass", "0123456789", "TRAN THI B", 5_000_000),
    DemoUser("mallory", "mallory-pass", "0999888777", "LE VAN M", 0),
)


def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    salt = secrets.token_bytes(16) if salt is None else salt
    return salt, hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT)


def seed_demo_users(conn) -> None:
    for u in DEMO_USERS:
        if conn.execute("SELECT 1 FROM users WHERE username = ?", (u.username,)).fetchone():
            continue
        salt, pw_hash = hash_password(u.password)
        conn.execute(
            "INSERT INTO users (username, pw_salt, pw_hash, account, display_name, balance) VALUES (?, ?, ?, ?, ?, ?)",
            (u.username, salt, pw_hash, u.account, u.name, u.balance),
        )


def authenticate(conn, username: str, password: str):
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        hash_password(password)  # spend the same time as a real check
        return None
    _, candidate = hash_password(password, bytes(row["pw_salt"]))
    return row if hmac.compare_digest(candidate, bytes(row["pw_hash"])) else None


def create_session(conn, user_id: int, now: int, ttl: int) -> str:
    token = secrets.token_urlsafe(32)
    conn.execute("INSERT INTO sessions (token, user_id, exp) VALUES (?, ?, ?)", (token, user_id, now + ttl))
    return token


def user_for_session(conn, token: str, now: int):
    return conn.execute(
        "SELECT users.* FROM sessions JOIN users ON users.id = sessions.user_id "
        "WHERE sessions.token = ? AND sessions.exp >= ?",
        (token, now),
    ).fetchone()


def delete_session(conn, token: str | None) -> None:
    if token:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


def create_enroll_token(conn, user_id: int, now: int, ttl: int) -> str:
    token = secrets.token_urlsafe(24)
    conn.execute("INSERT INTO enroll_tokens (token, user_id, exp) VALUES (?, ?, ?)", (token, user_id, now + ttl))
    return token


def enroll_device(conn, token: str, public_key_raw: bytes, now: int) -> tuple[str, bytes, bytes] | None:
    with write_tx(conn):
        row = conn.execute("SELECT * FROM enroll_tokens WHERE token = ?", (token,)).fetchone()
        if row is None or row["used"] or now > row["exp"]:
            audit(conn, now, row["user_id"] if row else None, None, "enroll_rejected", "invalid token")
            return None
        conn.execute("UPDATE enroll_tokens SET used = 1 WHERE token = ?", (token,))
        device_id = str(uuid.uuid4())
        k_totp, k_hmac = secrets.token_bytes(20), secrets.token_bytes(32)
        conn.execute("DELETE FROM devices WHERE user_id = ?", (row["user_id"],))
        conn.execute(
            "INSERT INTO devices (id, user_id, public_key, k_totp, k_hmac, last_totp_step, created_at) "
            "VALUES (?, ?, ?, ?, ?, NULL, ?)",
            (device_id, row["user_id"], public_key_raw, k_totp, k_hmac, now),
        )
        audit(conn, now, row["user_id"], None, "device_enrolled", device_id)
        return device_id, k_totp, k_hmac


def device_for_user(conn, user_id: int):
    return conn.execute("SELECT * FROM devices WHERE user_id = ?", (user_id,)).fetchone()
