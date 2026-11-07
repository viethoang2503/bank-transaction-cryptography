import pytest

from server import auth, db, transfers
from server.config import Settings


@pytest.fixture
def env(tmp_path):
    path = str(tmp_path / "t.sqlite3")
    db.init_db(path)
    conn = db.connect(path)
    auth.seed_demo_users(conn)
    alice = auth.authenticate(conn, "alice", "alice-pass")
    settings = Settings(mode="hmac", db_path=path)
    return conn, settings, alice


def _enroll(conn, user):
    auth.enroll_device(conn, auth.create_enroll_token(conn, user["id"], 0, 300), b"\x04" + bytes(64), 1)


def test_requires_device(env):
    conn, settings, alice = env
    with pytest.raises(transfers.TransferError, match="Enroll"):
        transfers.create_transfer(conn, settings, alice, "0123456789", "1000", 100)


def test_creates_pending_tx_with_server_side_name(env):
    conn, settings, alice = env
    _enroll(conn, alice)
    tx = transfers.create_transfer(conn, settings, alice, "0123456789", "1000000", 100)
    assert tx["to_name"] == "TRAN THI B" and tx["amount"] == 1_000_000 and tx["exp"] == 220
    assert transfers.get_tx_for_user(conn, tx["tx_id"], alice["id"]) == tx
    assert transfers.current_state(conn, tx["tx_id"], alice["id"], 220) == "pending"
    assert transfers.current_state(conn, tx["tx_id"], alice["id"], 221) == "expired"


@pytest.mark.parametrize("to,amount,msg", [
    ("12", "1000", "Invalid account"),
    ("0123456789", "-5", "Invalid amount"),
    ("0123456789", "1e6", "Invalid amount"),
    ("0123456789", "0", "Invalid amount"),
    ("0011223344", "1000", "own account"),
    ("0000000000", "1000", "Unknown recipient"),
    ("0123456789", "100000001", "Insufficient"),
])
def test_rejects_bad_input(env, to, amount, msg):
    conn, settings, alice = env
    _enroll(conn, alice)
    with pytest.raises(transfers.TransferError, match=msg):
        transfers.create_transfer(conn, settings, alice, to, amount, 100)


def test_other_user_cannot_read_tx(env):
    conn, settings, alice = env
    _enroll(conn, alice)
    tx = transfers.create_transfer(conn, settings, alice, "0123456789", "1000", 100)
    bob = auth.authenticate(conn, "bob", "bob-pass")
    assert transfers.get_tx_for_user(conn, tx["tx_id"], bob["id"]) is None
    assert transfers.current_state(conn, tx["tx_id"], bob["id"], 100) is None
