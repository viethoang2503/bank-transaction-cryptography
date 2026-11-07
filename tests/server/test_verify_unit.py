import pytest

from server import auth, db, transfers
from server.config import Settings
from server.verify import Result, confirm_otp, confirm_signature
from tba_core.hmac_otp import tx_otp
from tba_core.signature import generate_p256, public_key_to_raw, sign_tx
from tba_core.totp import totp

NOW = 1_800_000_000


def setup(tmp_path, mode):
    path = str(tmp_path / f"{mode}.sqlite3")
    db.init_db(path)
    conn = db.connect(path)
    auth.seed_demo_users(conn)
    alice = auth.authenticate(conn, "alice", "alice-pass")
    sk = generate_p256()
    token = auth.create_enroll_token(conn, alice["id"], NOW, 300)
    device_id, k_totp, k_hmac = auth.enroll_device(conn, token, public_key_to_raw(sk.public_key()), NOW)
    settings = Settings(mode=mode, db_path=path)
    tx = transfers.create_transfer(conn, settings, alice, "0123456789", "1000000", NOW)
    return conn, settings, alice, tx, dict(sk=sk, device_id=device_id, k_totp=k_totp, k_hmac=k_hmac)


def balance(conn, account):
    return conn.execute("SELECT balance FROM users WHERE account = ?", (account,)).fetchone()[0]


def state(conn, tx_id):
    return conn.execute("SELECT state, attempts FROM transactions WHERE tx_id = ?", (tx_id,)).fetchone()


def test_hmac_correct_code_executes(tmp_path):
    conn, s, alice, tx, d = setup(tmp_path, "hmac")
    assert confirm_otp(conn, s, alice["id"], tx["tx_id"], tx_otp(d["k_hmac"], tx), NOW + 5) is Result.OK
    assert state(conn, tx["tx_id"])["state"] == "executed"
    assert balance(conn, "0123456789") == 6_000_000
    assert balance(conn, "0011223344") == 99_000_000


def test_hmac_code_for_other_tx_rejected(tmp_path):
    conn, s, alice, tx, d = setup(tmp_path, "hmac")
    forged = dict(tx, to="0999888777", to_name="LE VAN M")
    assert confirm_otp(conn, s, alice["id"], tx["tx_id"], tx_otp(d["k_hmac"], forged), NOW) is Result.REJECTED
    assert state(conn, tx["tx_id"])["attempts"] == 1


def test_lockout_after_three_failures(tmp_path):
    conn, s, alice, tx, d = setup(tmp_path, "hmac")
    for _ in range(3):
        confirm_otp(conn, s, alice["id"], tx["tx_id"], "00000000", NOW)
    assert state(conn, tx["tx_id"])["state"] == "failed"
    assert confirm_otp(conn, s, alice["id"], tx["tx_id"], tx_otp(d["k_hmac"], tx), NOW) is Result.REJECTED


def test_expired_rejected(tmp_path):
    conn, s, alice, tx, d = setup(tmp_path, "hmac")
    assert confirm_otp(conn, s, alice["id"], tx["tx_id"], tx_otp(d["k_hmac"], tx), NOW + 121) is Result.REJECTED
    assert state(conn, tx["tx_id"])["state"] == "expired"


def test_replay_on_executed_tx_rejected(tmp_path):
    conn, s, alice, tx, d = setup(tmp_path, "hmac")
    code = tx_otp(d["k_hmac"], tx)
    assert confirm_otp(conn, s, alice["id"], tx["tx_id"], code, NOW) is Result.OK
    assert confirm_otp(conn, s, alice["id"], tx["tx_id"], code, NOW) is Result.REJECTED
    assert balance(conn, "0123456789") == 6_000_000


def test_baseline_totp_and_step_reuse(tmp_path):
    conn, s, alice, tx, d = setup(tmp_path, "baseline")
    code = totp(d["k_totp"], NOW)
    assert confirm_otp(conn, s, alice["id"], tx["tx_id"], code, NOW) is Result.OK
    tx2 = transfers.create_transfer(conn, s, alice, "0123456789", "1000", NOW)
    assert confirm_otp(conn, s, alice["id"], tx2["tx_id"], code, NOW) is Result.REJECTED


def test_otp_not_accepted_in_sig_mode(tmp_path):
    conn, s, alice, tx, d = setup(tmp_path, "sig")
    assert confirm_otp(conn, s, alice["id"], tx["tx_id"], tx_otp(d["k_hmac"], tx), NOW) is Result.REJECTED


@pytest.mark.parametrize("mode", ["sig", "sig_blind"])
def test_signature_executes_and_stores_evidence(tmp_path, mode):
    conn, s, alice, tx, d = setup(tmp_path, mode)
    sig = sign_tx(d["sk"], tx)
    assert confirm_signature(conn, s, d["device_id"], tx["tx_id"], sig, NOW) is Result.OK
    row = conn.execute("SELECT state, evidence FROM transactions WHERE tx_id = ?", (tx["tx_id"],)).fetchone()
    assert row["state"] == "executed" and bytes(row["evidence"]) == sig


def test_signature_over_forged_tx_rejected(tmp_path):
    conn, s, alice, tx, d = setup(tmp_path, "sig")
    forged = dict(tx, to="0999888777", to_name="LE VAN M")
    assert confirm_signature(conn, s, d["device_id"], tx["tx_id"], sign_tx(d["sk"], forged), NOW) is Result.REJECTED


def test_unknown_device_and_wrong_mode_rejected(tmp_path):
    conn, s, alice, tx, d = setup(tmp_path, "hmac")
    sig = sign_tx(d["sk"], tx)
    assert confirm_signature(conn, s, "no-such-device", tx["tx_id"], sig, NOW) is Result.REJECTED
    assert confirm_signature(conn, s, d["device_id"], tx["tx_id"], sig, NOW) is Result.REJECTED


def test_audit_log_records_reasons(tmp_path):
    conn, s, alice, tx, d = setup(tmp_path, "hmac")
    confirm_otp(conn, s, alice["id"], tx["tx_id"], "12345678", NOW)
    events = [r["event"] for r in conn.execute("SELECT event FROM audit_log ORDER BY id")]
    assert "confirm_failed" in events
