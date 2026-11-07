import re

import pytest

from server.config import Settings
from server.testing import FakeClock, make_clients
from tba_core.b64 import b64url_decode, b64url_encode
from tba_core.encoding import decode_qr_payload
from tba_core.hmac_otp import tx_otp
from tba_core.signature import generate_p256, public_key_to_raw, sign_tx
from tba_core.totp import totp

QR = re.compile(r'data-payload="([^"]+)"')


@pytest.fixture
def make(tmp_path):
    def _make(mode):
        clock = FakeClock()
        app, browser, phone = make_clients(Settings(mode=mode, db_path=str(tmp_path / f"{mode}.db")), clock)
        return clock, browser, phone
    return _make


def login(browser):
    r = browser.post("/login", data={"username": "alice", "password": "alice-pass"}, follow_redirects=False)
    assert r.status_code == 303
    assert "secure" in r.headers["set-cookie"].lower() and "httponly" in r.headers["set-cookie"].lower()


def enroll(browser, phone):
    payload = QR.search(browser.get("/enroll").text).group(1)
    sk = generate_p256()
    r = phone.post("/api/device/enroll", json={"token": payload.split(":", 1)[1],
                                               "public_key": b64url_encode(public_key_to_raw(sk.public_key()))})
    assert r.status_code == 200
    d = r.json()
    return sk, d["device_id"], b64url_decode(d["k_totp"]), b64url_decode(d["k_hmac"])


def start_transfer(browser, to="0123456789", amount="1000000"):
    r = browser.post("/transfer", data={"to": to, "amount": amount}, follow_redirects=False)
    assert r.status_code == 303, r.text
    tx_id = r.headers["location"].rsplit("/", 1)[1]
    m = QR.search(browser.get(f"/transfer/{tx_id}").text)
    return tx_id, (m.group(1) if m else None)


def test_login_required(make):
    _, browser, _ = make("sig")
    assert browser.get("/transfer", follow_redirects=False).status_code == 303
    r = browser.post("/login", data={"username": "alice", "password": "x"})
    assert r.status_code == 401


def test_config_endpoint(make):
    _, _, phone = make("hmac")
    assert phone.get("/api/config").json() == {"mode": "hmac", "otp_digits": 8, "totp_digits": 6}


def test_enroll_rejects_bad_key_and_reused_token(make):
    _, browser, phone = make("sig")
    login(browser)
    token = QR.search(browser.get("/enroll").text).group(1).split(":", 1)[1]
    bad = phone.post("/api/device/enroll", json={"token": token, "public_key": b64url_encode(b"\x04" + b"\x01" * 64)})
    assert bad.status_code == 400
    good_key = b64url_encode(public_key_to_raw(generate_p256().public_key()))
    assert phone.post("/api/device/enroll", json={"token": token, "public_key": good_key}).status_code == 200
    assert phone.post("/api/device/enroll", json={"token": token, "public_key": good_key}).status_code == 403


def test_lookup(make):
    _, browser, _ = make("sig")
    login(browser)
    assert browser.get("/api/lookup", params={"account": "0123456789"}).json() == {"account": "0123456789", "name": "TRAN THI B"}
    assert browser.get("/api/lookup", params={"account": "0000000000"}).status_code == 404


def test_baseline_flow(make):
    clock, browser, phone = make("baseline")
    login(browser)
    _, _, k_totp, _ = enroll(browser, phone)
    tx_id, qr = start_transfer(browser)
    assert qr is None
    r = browser.post(f"/transfer/{tx_id}/otp", data={"otp": totp(k_totp, clock())})
    assert r.status_code == 200 and "Transfer completed" in r.text


def test_hmac_flow_accepts_spaces(make):
    clock, browser, phone = make("hmac")
    login(browser)
    _, _, _, k_hmac = enroll(browser, phone)
    tx_id, qr = start_transfer(browser)
    tx = decode_qr_payload(qr)
    assert tx["tx_id"] == tx_id and tx["to_name"] == "TRAN THI B"
    code = tx_otp(k_hmac, tx)
    r = browser.post(f"/transfer/{tx_id}/otp", data={"otp": code[:4] + " " + code[4:]})
    assert r.status_code == 200
    assert browser.get(f"/transfer/{tx_id}/status").json() == {"state": "executed"}


@pytest.mark.parametrize("mode", ["sig", "sig_blind"])
def test_sig_flow(make, mode):
    clock, browser, phone = make(mode)
    login(browser)
    sk, device_id, _, _ = enroll(browser, phone)
    tx_id, qr = start_transfer(browser)
    sig = b64url_encode(sign_tx(sk, decode_qr_payload(qr)))
    r = phone.post("/api/device/confirm", json={"device_id": device_id, "tx_id": tx_id, "signature": sig})
    assert r.json() == {"result": "ok"}
    assert "Transfer completed" in browser.get(f"/transfer/{tx_id}/result").text


def test_confirm_never_500(make):
    _, browser, phone = make("sig")
    login(browser)
    _, device_id, _, _ = enroll(browser, phone)
    tx_id, _ = start_transfer(browser)
    for body in [{"device_id": device_id, "tx_id": tx_id, "signature": "***"},
                 {"device_id": device_id, "tx_id": tx_id, "signature": ""},
                 {"device_id": device_id, "tx_id": tx_id},
                 {"device_id": 1, "tx_id": None, "signature": []}]:
        assert phone.post("/api/device/confirm", json=body).status_code < 500


def test_status_expires(make):
    clock, browser, phone = make("sig")
    login(browser)
    enroll(browser, phone)
    tx_id, _ = start_transfer(browser)
    clock.advance(121)
    assert browser.get(f"/transfer/{tx_id}/status").json() == {"state": "expired"}


def test_transfer_form_error(make):
    _, browser, phone = make("sig")
    login(browser)
    enroll(browser, phone)
    r = browser.post("/transfer", data={"to": "0000000000", "amount": "10"})
    assert r.status_code == 400 and "Unknown recipient" in r.text
