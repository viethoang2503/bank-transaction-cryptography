import re
from dataclasses import dataclass
from pathlib import Path

from server.config import Settings
from server.db import connect
from server.testing import FakeClock, make_clients

from .virtual_phone import VirtualPhone

_QR = re.compile(r'data-payload="([^"]+)"')


@dataclass
class Pending:
    tx_id: str
    qr_payload: str | None


class Lab:
    """One fresh bank (own SQLite file, fake clock) plus a browser and a phone HTTP client."""

    def __init__(self, mode: str, workdir: Path):
        self.mode = mode
        self.clock = FakeClock()
        self.db_path = Path(workdir) / f"{mode}.sqlite3"
        self.settings = Settings(mode=mode, db_path=str(self.db_path))
        self.app, self.browser, self.phone_http = make_clients(self.settings, self.clock)

    def login(self, username: str = "alice", password: str = "alice-pass") -> None:
        r = self.browser.post("/login", data={"username": username, "password": password}, follow_redirects=False)
        assert r.status_code == 303, r.text

    def enroll_phone(self) -> VirtualPhone:
        payload = _QR.search(self.browser.get("/enroll").text).group(1)
        phone = VirtualPhone(self.phone_http, self.mode, self.clock)
        phone.enroll(payload)
        return phone

    def create_transfer(self, to: str, amount: int, mitb=None) -> Pending:
        form = {"to": to, "amount": str(amount)}
        if mitb is not None:
            form = mitb.rewrite_request(form)
        r = self.browser.post("/transfer", data=form, follow_redirects=False)
        assert r.status_code == 303, r.text
        tx_id = r.headers["location"].rsplit("/", 1)[1]
        match = _QR.search(self.browser.get(f"/transfer/{tx_id}").text)
        qr = match.group(1) if match else None
        if mitb is not None and qr is not None:
            qr = mitb.rewrite_qr(qr)
        return Pending(tx_id, qr)

    def submit_otp(self, tx_id: str, code: str) -> int:
        return self.browser.post(f"/transfer/{tx_id}/otp", data={"otp": code}).status_code

    def post_signature(self, device_id: str, tx_id: str, signature_b64: str):
        return self.phone_http.post("/api/device/confirm",
                                    json={"device_id": device_id, "tx_id": tx_id, "signature": signature_b64})

    def state(self, tx_id: str) -> str:
        return self.browser.get(f"/transfer/{tx_id}/status").json()["state"]

    def _query(self, sql: str, args=()):
        conn = connect(str(self.db_path))
        try:
            return conn.execute(sql, args).fetchone()
        finally:
            conn.close()

    def balance(self, account: str) -> int:
        return self._query("SELECT balance FROM users WHERE account = ?", (account,))["balance"]

    def user_id(self, username: str = "alice") -> int:
        return self._query("SELECT id FROM users WHERE username = ?", (username,))["id"]

    def device_row(self, username: str = "alice"):
        return self._query("SELECT * FROM devices WHERE user_id = ?", (self.user_id(username),))

    def tx_row(self, tx_id: str):
        return self._query("SELECT * FROM transactions WHERE tx_id = ?", (tx_id,))
