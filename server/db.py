import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  pw_salt BLOB NOT NULL,
  pw_hash BLOB NOT NULL,
  account TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  balance INTEGER NOT NULL CHECK (balance >= 0)
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  exp INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS enroll_tokens (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  exp INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  user_id INTEGER UNIQUE NOT NULL REFERENCES users(id),
  public_key BLOB NOT NULL,
  k_totp BLOB NOT NULL,
  k_hmac BLOB NOT NULL,
  last_totp_step INTEGER,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS transactions (
  tx_id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  mode TEXT NOT NULL,
  canonical BLOB NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending', 'executed', 'failed', 'expired')),
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  evidence BLOB
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  user_id INTEGER,
  tx_id TEXT,
  event TEXT NOT NULL,
  detail TEXT
);
"""


def connect(path: str) -> sqlite3.Connection:
    # Autocommit mode; multi-statement changes use write_tx().
    conn = sqlite3.connect(path, isolation_level=None, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(path: str) -> None:
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()


@contextmanager
def write_tx(conn: sqlite3.Connection):
    """Serialize writers: BEGIN IMMEDIATE takes the write lock up front."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def audit(conn, ts: int, user_id, tx_id, event: str, detail: str = "") -> None:
    conn.execute(
        "INSERT INTO audit_log (ts, user_id, tx_id, event, detail) VALUES (?, ?, ?, ?, ?)",
        (ts, user_id, tx_id, event, detail),
    )
