from server import auth, db


def _conn(tmp_path):
    path = str(tmp_path / "t.sqlite3")
    db.init_db(path)
    conn = db.connect(path)
    auth.seed_demo_users(conn)
    return conn


def test_seed_is_idempotent(tmp_path):
    conn = _conn(tmp_path)
    auth.seed_demo_users(conn)
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 3


def test_authenticate(tmp_path):
    conn = _conn(tmp_path)
    assert auth.authenticate(conn, "alice", "alice-pass")["account"] == "0011223344"
    assert auth.authenticate(conn, "alice", "wrong") is None
    assert auth.authenticate(conn, "nobody", "x") is None


def test_session_expiry(tmp_path):
    conn = _conn(tmp_path)
    uid = auth.authenticate(conn, "alice", "alice-pass")["id"]
    token = auth.create_session(conn, uid, now=1000, ttl=60)
    assert auth.user_for_session(conn, token, 1060)["username"] == "alice"
    assert auth.user_for_session(conn, token, 1061) is None


def test_enroll_token_single_use_and_expiry(tmp_path):
    conn = _conn(tmp_path)
    uid = auth.authenticate(conn, "alice", "alice-pass")["id"]
    token = auth.create_enroll_token(conn, uid, now=1000, ttl=300)
    device_id, k_totp, k_hmac = auth.enroll_device(conn, token, b"\x04" + bytes(64), now=1001)
    assert len(k_totp) == 20 and len(k_hmac) == 32
    assert auth.device_for_user(conn, uid)["id"] == device_id
    assert auth.enroll_device(conn, token, b"\x04" + bytes(64), now=1002) is None
    bob = auth.authenticate(conn, "bob", "bob-pass")["id"]
    late = auth.create_enroll_token(conn, bob, now=1000, ttl=300)
    assert auth.enroll_device(conn, late, b"\x04" + bytes(64), now=1301) is None
    assert auth.device_for_user(conn, bob) is None


def test_reenroll_is_rejected_and_keeps_first_device(tmp_path):
    conn = _conn(tmp_path)
    uid = auth.authenticate(conn, "alice", "alice-pass")["id"]
    first = auth.enroll_device(conn, auth.create_enroll_token(conn, uid, 0, 300), b"\x04" + bytes(64), 1)[0]
    assert auth.enroll_device(conn, auth.create_enroll_token(conn, uid, 0, 300), b"\x04" + bytes(64), 1) is None
    assert auth.device_for_user(conn, uid)["id"] == first
    details = [r["detail"] for r in conn.execute("SELECT detail FROM audit_log WHERE event = 'enroll_rejected'")]
    assert details == ["device already enrolled"]
