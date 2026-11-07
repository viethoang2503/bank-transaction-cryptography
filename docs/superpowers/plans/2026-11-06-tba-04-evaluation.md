# Plan 04: Security evaluation, MitB, benchmarks

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Chạy tự động kịch bản S1-S13 trên cả 4 chế độ, so với bảng kỳ vọng, sinh bảng/hình cho report; cung cấp addon MitB cho demo thật; đo brute-force, hiệu năng, kích thước.

**Architecture:** `Lab` dựng một server thật (`create_app` + `TestClient`, đồng hồ giả) cho mỗi lần chạy. `VirtualPhone` đóng vai authenticator bằng `tba_core`. `Mitb` sửa request/QR giữa trình duyệt và server. Mỗi kịch bản là một hàm `(mode, workdir) -> outcome`. `run_scenarios` chạy ma trận và ghi `results/`.

**Tech Stack:** Python 3.11+, pytest, matplotlib, segno, mitmproxy ≥ 10 (cài riêng bằng pipx), ProVerif (tùy chọn).

**Spec:** `docs/superpowers/specs/2026-11-06-tba-midterm-design.md` (mục 5, 6)

## Global Constraints

- Outcome hợp lệ: `ok`, `blocked`, `succeeded`, `yes`, `no`, `n/a`, `broken`.
- Bảng kỳ vọng đúng như spec mục 6; `make scenarios` trả mã lỗi khác 0 nếu kết quả thực tế lệch kỳ vọng.
- Không sửa code server để làm kịch bản "đẹp hơn". Nếu kết quả lệch, báo cả nhóm và ghi vào report.
- Mọi số liệu trong report lấy từ `results/`.

## File structure

| File | Trách nhiệm |
|---|---|
| `evaluation/outcomes.py` | Hằng số outcome, `MODES`, tài khoản demo |
| `evaluation/virtual_phone.py` | `VirtualPhone` |
| `evaluation/mitb.py` | `Mitb`, `forge_qr` |
| `evaluation/harness.py` | `Lab`, `Pending` |
| `evaluation/user_model.py` | `attentive_user`, `careless_user` |
| `evaluation/flows.py` | `run_transfer` |
| `evaluation/scenarios.py` | S1-S13 và `SCENARIOS` |
| `evaluation/expected.py` | `EXPECTED` |
| `evaluation/goals.py` | Ánh xạ G1-G7 |
| `evaluation/latex.py` | Sinh bảng LaTeX |
| `evaluation/run_scenarios.py` | Chạy ma trận, ghi kết quả |
| `evaluation/bruteforce.py` | Thí nghiệm S9 |
| `evaluation/bench.py`, `evaluation/sizes.py` | P1, P3 |
| `attacker/mitb_addon.py` | Addon mitmproxy |
| `proverif/*.pv` | Tùy chọn |
| `tests/evaluation/*.py` | Test |

---

### Task 1: Hằng số, VirtualPhone, Mitb (TV5)

**Files:**
- Create: `evaluation/outcomes.py`, `evaluation/virtual_phone.py`, `evaluation/mitb.py`
- Test: `tests/evaluation/__init__.py`, `tests/evaluation/test_mitb.py`

**Interfaces:**
- Consumes: `tba_core.*`; `server.auth.DEMO_USERS`
- Produces:
  - `MODES`, `SIG_MODES`, `OK, BLOCKED, SUCCEEDED, YES, NO, NA, BROKEN`, `ALICE, BOB, MALLORY` (các `DemoUser`)
  - `VirtualPhone(http, mode, clock)` với `enroll(payload)`, `screen(qr_payload) -> dict | None`, `totp_code() -> str`, `hmac_code(qr_payload) -> str`, `sign(tx) -> bytes`, `send_signature(tx_id, signature: bytes) -> Response`, `sign_and_send(qr_payload) -> str`, thuộc tính `device_id`, `k_totp`, `k_hmac`, `last_signature`
  - `Mitb(attacker_to=MALLORY.account, attacker_amount=None, forge_qr=False, intended_name="")` với `rewrite_request(form) -> dict`, `rewrite_qr(payload) -> str`; `forge_qr(payload, to, to_name, amount) -> str`

- [ ] **Step 1: Viết test thất bại `tests/evaluation/test_mitb.py`** (tạo `tests/evaluation/__init__.py` rỗng)

```python
from evaluation.mitb import Mitb, forge_qr
from evaluation.outcomes import BOB, MALLORY
from tba_core.challenge import new_tx
from tba_core.encoding import decode_qr_payload, encode_qr_payload


def test_rewrite_request_swaps_recipient_and_remembers_intent():
    m = Mitb()
    out = m.rewrite_request({"to": BOB.account, "amount": "1000000"})
    assert out == {"to": MALLORY.account, "amount": "1000000"}
    assert m.intended_to == BOB.account and m.intended_amount == 1_000_000


def test_rewrite_amount_only():
    m = Mitb(attacker_to=None, attacker_amount=9_000_000)
    assert m.rewrite_request({"to": BOB.account, "amount": "1000000"}) == {"to": BOB.account, "amount": "9000000"}


def test_forge_qr_restores_intended_details():
    real = new_tx("0011223344", MALLORY.account, MALLORY.name, 1_000_000, now=1_800_000_000)
    forged = decode_qr_payload(forge_qr(encode_qr_payload(real), BOB.account, BOB.name, 1_000_000))
    assert forged["to"] == BOB.account and forged["to_name"] == BOB.name
    assert forged["tx_id"] == real["tx_id"] and forged["nonce"] == real["nonce"]


def test_rewrite_qr_is_identity_unless_forging():
    real = encode_qr_payload(new_tx("0011223344", MALLORY.account, MALLORY.name, 1, now=1))
    assert Mitb().rewrite_qr(real) == real
```

- [ ] **Step 2: Chạy để thấy test thất bại**

Run: `pytest tests/evaluation/test_mitb.py -q`
Expected: FAIL với `ModuleNotFoundError`

- [ ] **Step 3: Cài đặt `evaluation/outcomes.py`**

```python
from server.auth import DEMO_USERS

MODES = ("baseline", "hmac", "sig", "sig_blind")
SIG_MODES = ("sig", "sig_blind")

OK = "ok"
BLOCKED = "blocked"
SUCCEEDED = "succeeded"
YES = "yes"
NO = "no"
NA = "n/a"
BROKEN = "broken"

GOOD = {OK, BLOCKED, YES}
BAD = {SUCCEEDED, NO, BROKEN}

ALICE, BOB, MALLORY = DEMO_USERS
```

- [ ] **Step 4: Cài đặt `evaluation/virtual_phone.py`**

```python
"""A scripted authenticator built on tba_core. It behaves like authenticator/js/app.js."""
from tba_core.b64 import b64url_decode, b64url_encode
from tba_core.encoding import decode_qr_payload
from tba_core.hmac_otp import tx_otp
from tba_core.signature import generate_p256, public_key_to_raw, sign_tx
from tba_core.totp import totp


class VirtualPhone:
    def __init__(self, http, mode: str, clock):
        self.http = http
        self.mode = mode
        self.clock = clock
        self._sk = generate_p256()
        self.device_id = None
        self.k_totp = None
        self.k_hmac = None
        self.last_signature = None
        config = http.get("/api/config").json()
        self.otp_digits = config["otp_digits"]
        self.totp_digits = config["totp_digits"]

    def enroll(self, enroll_payload: str) -> None:
        prefix = "tbaenroll1:"
        assert enroll_payload.startswith(prefix), enroll_payload
        r = self.http.post("/api/device/enroll", json={
            "token": enroll_payload[len(prefix):],
            "public_key": b64url_encode(public_key_to_raw(self._sk.public_key())),
        })
        r.raise_for_status()
        data = r.json()
        self.device_id = data["device_id"]
        self.k_totp = b64url_decode(data["k_totp"])
        self.k_hmac = b64url_decode(data["k_hmac"])

    def screen(self, qr_payload: str | None) -> dict | None:
        """What the user sees on the phone: nothing in baseline and sig_blind."""
        if self.mode in ("baseline", "sig_blind") or qr_payload is None:
            return None
        return decode_qr_payload(qr_payload)

    def totp_code(self) -> str:
        return totp(self.k_totp, self.clock(), digits=self.totp_digits)

    def hmac_code(self, qr_payload: str) -> str:
        return tx_otp(self.k_hmac, decode_qr_payload(qr_payload), digits=self.otp_digits)

    def sign(self, tx: dict) -> bytes:
        return sign_tx(self._sk, tx)

    def send_signature(self, tx_id: str, signature: bytes):
        return self.http.post("/api/device/confirm", json={
            "device_id": self.device_id, "tx_id": tx_id, "signature": b64url_encode(signature),
        })

    def sign_and_send(self, qr_payload: str) -> str:
        tx = decode_qr_payload(qr_payload)
        self.last_signature = self.sign(tx)
        return self.send_signature(tx["tx_id"], self.last_signature).json()["result"]
```

- [ ] **Step 5: Cài đặt `evaluation/mitb.py`**

```python
"""Man-in-the-browser model used by automated scenarios.

attacker/mitb_addon.py does the same rewriting on real HTTP traffic.
"""
from dataclasses import dataclass

from tba_core.encoding import decode_qr_payload, encode_qr_payload

from .outcomes import MALLORY


def forge_qr(payload: str, to: str, to_name: str, amount: int) -> str:
    tx = decode_qr_payload(payload)
    tx.update({"to": to, "to_name": to_name, "amount": amount})
    return encode_qr_payload(tx)


@dataclass
class Mitb:
    attacker_to: str | None = MALLORY.account
    attacker_amount: int | None = None
    forge_qr: bool = False
    intended_name: str = ""
    intended_to: str = ""
    intended_amount: int = 0

    def rewrite_request(self, form: dict) -> dict:
        self.intended_to = form["to"]
        self.intended_amount = int(form["amount"])
        out = dict(form)
        if self.attacker_to is not None:
            out["to"] = self.attacker_to
        if self.attacker_amount is not None:
            out["amount"] = str(self.attacker_amount)
        return out

    def rewrite_qr(self, payload: str) -> str:
        if not self.forge_qr:
            return payload
        return forge_qr(payload, self.intended_to, self.intended_name, self.intended_amount)
```

- [ ] **Step 6: Chạy test**

Run: `pytest tests/evaluation/test_mitb.py -q`
Expected: tất cả PASS

- [ ] **Step 7: Commit**

```bash
git add evaluation/outcomes.py evaluation/virtual_phone.py evaluation/mitb.py tests/evaluation
git commit -m "feat(eval): virtual phone and MitB model"
```

---

### Task 2: Lab, user model, run_transfer (TV5)

**Files:**
- Create: `evaluation/harness.py`, `evaluation/user_model.py`, `evaluation/flows.py`
- Test: `tests/evaluation/test_harness.py`

**Interfaces:**
- Consumes: `server.testing.FakeClock`, `make_clients`; `server.config.Settings`; `server.db.connect`; Task 1
- Produces:
  - `@dataclass Pending(tx_id: str, qr_payload: str | None)`
  - `Lab(mode, workdir: Path)` với `clock`, `settings`, `db_path`, `browser`, `phone_http`; `login(username="alice", password="alice-pass")`, `enroll_phone() -> VirtualPhone`, `create_transfer(to, amount, mitb=None) -> Pending`, `submit_otp(tx_id, code) -> int`, `post_signature(device_id, tx_id, signature_b64) -> Response`, `state(tx_id) -> str`, `balance(account) -> int`, `user_id(username) -> int`, `device_row() -> Row`, `tx_row(tx_id) -> Row`
  - `attentive_user(intended: dict, screen: dict | None) -> bool`, `careless_user(intended, screen) -> bool`
  - `run_transfer(lab, phone, user, to, amount, mitb=None) -> tuple[str, str]` (tx_id, state)

- [ ] **Step 1: Viết test thất bại `tests/evaluation/test_harness.py`**

```python
import pytest

from evaluation.flows import run_transfer
from evaluation.harness import Lab
from evaluation.mitb import Mitb
from evaluation.outcomes import BOB, MALLORY, MODES
from evaluation.user_model import attentive_user, careless_user


@pytest.mark.parametrize("mode", MODES)
def test_honest_transfer_executes(tmp_path, mode):
    lab = Lab(mode, tmp_path)
    lab.login()
    phone = lab.enroll_phone()
    before = lab.balance(BOB.account)
    _, state = run_transfer(lab, phone, attentive_user, BOB.account, 1_000_000)
    assert state == "executed"
    assert lab.balance(BOB.account) == before + 1_000_000


def test_attentive_user_rejects_mismatch():
    assert attentive_user({"to": "1", "amount": 5}, {"to": "1", "amount": 5})
    assert not attentive_user({"to": "1", "amount": 5}, {"to": "2", "amount": 5})
    assert not attentive_user({"to": "1", "amount": 5}, {"to": "1", "amount": 6})
    assert attentive_user({"to": "1", "amount": 5}, None)
    assert careless_user({"to": "1", "amount": 5}, {"to": "2", "amount": 9})


def test_mitb_redirects_baseline(tmp_path):
    lab = Lab("baseline", tmp_path)
    lab.login()
    phone = lab.enroll_phone()
    run_transfer(lab, phone, attentive_user, BOB.account, 1_000_000, mitb=Mitb())
    assert lab.balance(MALLORY.account) == 1_000_000
```

- [ ] **Step 2: Chạy để thấy test thất bại**

Run: `pytest tests/evaluation/test_harness.py -q`
Expected: FAIL với `ModuleNotFoundError`

- [ ] **Step 3: Cài đặt `evaluation/harness.py`**

```python
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
```

- [ ] **Step 4: Cài đặt `evaluation/user_model.py`**

```python
"""User decision models for the confirmation step.

`intended` is what the user meant to do: {"to": ..., "amount": ...}.
`screen` is what the phone shows, or None when it shows nothing.
"""


def attentive_user(intended: dict, screen: dict | None) -> bool:
    if screen is None:  # blind signing: nothing to compare, the user approves
        return True
    return screen["to"] == intended["to"] and screen["amount"] == intended["amount"]


def careless_user(intended: dict, screen: dict | None) -> bool:
    return True
```

- [ ] **Step 5: Cài đặt `evaluation/flows.py`**

```python
from .harness import Lab, Pending
from .outcomes import SIG_MODES


def run_transfer(lab: Lab, phone, user, to: str, amount: int, mitb=None) -> tuple[str, str]:
    pending: Pending = lab.create_transfer(to, amount, mitb)
    intended = {"to": to, "amount": amount}
    if lab.mode == "baseline":
        # The phone shows only a code; the browser shows whatever the MitB wants,
        # so the user's view matches their intent and they always type the code.
        lab.submit_otp(pending.tx_id, phone.totp_code())
    elif user(intended, phone.screen(pending.qr_payload)):
        if lab.mode == "hmac":
            lab.submit_otp(pending.tx_id, phone.hmac_code(pending.qr_payload))
        elif lab.mode in SIG_MODES:
            phone.sign_and_send(pending.qr_payload)
    return pending.tx_id, lab.state(pending.tx_id)
```

- [ ] **Step 6: Chạy test**

Run: `pytest tests/evaluation/test_harness.py -q`
Expected: tất cả PASS

- [ ] **Step 7: Commit**

```bash
git add evaluation/harness.py evaluation/user_model.py evaluation/flows.py tests/evaluation/test_harness.py
git commit -m "feat(eval): lab harness, user models and transfer flow"
```

---

### Task 3: Kịch bản S1-S13 và bảng kỳ vọng (TV5)

**Files:**
- Create: `evaluation/scenarios.py`, `evaluation/expected.py`
- Test: `tests/evaluation/test_scenarios.py`

**Interfaces:**
- Consumes: Task 1-2; `server.verify`; `tba_core.*`; `shared/vectors.json`
- Produces: `SCENARIOS: dict[str, tuple[str, Callable[[str, Path], str]]]` (id → (mô tả tiếng Anh, hàm)); `EXPECTED: dict[str, dict[str, str]]`

- [ ] **Step 1: Viết `evaluation/expected.py`** (chép đúng bảng trong spec mục 6)

```python
from .outcomes import BLOCKED, NA, NO, OK, SUCCEEDED, YES

_ALL_BLOCKED = {"baseline": BLOCKED, "hmac": BLOCKED, "sig": BLOCKED, "sig_blind": BLOCKED}

EXPECTED = {
    "S1": {"baseline": OK, "hmac": OK, "sig": OK, "sig_blind": OK},
    "S2a": {"baseline": SUCCEEDED, "hmac": BLOCKED, "sig": BLOCKED, "sig_blind": SUCCEEDED},
    "S2b": {"baseline": SUCCEEDED, "hmac": SUCCEEDED, "sig": SUCCEEDED, "sig_blind": SUCCEEDED},
    "S3": {"baseline": SUCCEEDED, "hmac": BLOCKED, "sig": BLOCKED, "sig_blind": SUCCEEDED},
    "S4": {"baseline": SUCCEEDED, "hmac": BLOCKED, "sig": BLOCKED, "sig_blind": BLOCKED},
    "S5": {"baseline": SUCCEEDED, "hmac": BLOCKED, "sig": BLOCKED, "sig_blind": BLOCKED},
    "S6": dict(_ALL_BLOCKED),
    "S7": dict(_ALL_BLOCKED),
    "S8": dict(_ALL_BLOCKED),
    "S9": dict(_ALL_BLOCKED),
    "S10": {"baseline": SUCCEEDED, "hmac": SUCCEEDED, "sig": BLOCKED, "sig_blind": BLOCKED},
    "S11": {"baseline": NO, "hmac": NO, "sig": YES, "sig_blind": YES},
    "S12": {"baseline": NA, "hmac": BLOCKED, "sig": BLOCKED, "sig_blind": BLOCKED},
    "S13": {"baseline": NA, "hmac": NA, "sig": BLOCKED, "sig_blind": BLOCKED},
}
```

- [ ] **Step 2: Viết test thất bại `tests/evaluation/test_scenarios.py`**

```python
import pytest

from evaluation.expected import EXPECTED
from evaluation.outcomes import MODES
from evaluation.scenarios import SCENARIOS


def test_registry_matches_expected():
    assert list(SCENARIOS) == list(EXPECTED)


@pytest.mark.parametrize("sid", list(EXPECTED))
@pytest.mark.parametrize("mode", MODES)
def test_scenario_outcome(tmp_path, sid, mode):
    _, fn = SCENARIOS[sid]
    assert fn(mode, tmp_path) == EXPECTED[sid][mode]
```

- [ ] **Step 3: Chạy để thấy test thất bại**

Run: `pytest tests/evaluation/test_scenarios.py -q`
Expected: FAIL với `ModuleNotFoundError: No module named 'evaluation.scenarios'`

- [ ] **Step 4: Cài đặt `evaluation/scenarios.py`**

```python
"""Attack scenarios. Each function builds a fresh Lab and returns one outcome string."""
import json
import secrets
import threading
import uuid
from pathlib import Path

from server import verify
from server.db import connect
from tba_core.b64 import b64url_encode
from tba_core.challenge import new_tx
from tba_core.encoding import EncodingError, decode_qr_payload, parse_canonical
from tba_core.hmac_otp import tx_otp, verify_tx_otp
from tba_core.signature import (
    P256_ORDER,
    generate_p256,
    public_key_from_raw,
    raw_to_der,
    sign_tx,
    verify_tx_signature,
)
from tba_core.totp import hotp, totp, totp_verify

from .flows import run_transfer
from .harness import Lab
from .mitb import Mitb
from .outcomes import ALICE, BLOCKED, BOB, BROKEN, MALLORY, NA, NO, OK, SIG_MODES, SUCCEEDED, YES
from .user_model import attentive_user, careless_user

AMOUNT = 1_000_000
VECTORS = Path(__file__).resolve().parents[1] / "shared" / "vectors.json"


def _setup(mode: str, workdir: Path):
    lab = Lab(mode, workdir)
    lab.login()
    return lab, lab.enroll_phone()


def _confirm_with_phone(lab, phone, pending) -> None:
    """The phone confirms whatever QR it was given (no user check)."""
    if lab.mode == "baseline":
        lab.submit_otp(pending.tx_id, phone.totp_code())
    elif lab.mode == "hmac":
        lab.submit_otp(pending.tx_id, phone.hmac_code(pending.qr_payload))
    else:
        phone.sign_and_send(pending.qr_payload)


def s1_honest(mode, workdir):
    lab, phone = _setup(mode, workdir)
    before = lab.balance(BOB.account)
    _, state = run_transfer(lab, phone, attentive_user, BOB.account, AMOUNT)
    return OK if state == "executed" and lab.balance(BOB.account) == before + AMOUNT else BROKEN


def _mitb_recipient(mode, workdir, user):
    lab, phone = _setup(mode, workdir)
    before = lab.balance(MALLORY.account)
    run_transfer(lab, phone, user, BOB.account, AMOUNT, mitb=Mitb())
    return SUCCEEDED if lab.balance(MALLORY.account) > before else BLOCKED


def s2a_mitb_recipient_attentive(mode, workdir):
    return _mitb_recipient(mode, workdir, attentive_user)


def s2b_mitb_recipient_careless(mode, workdir):
    return _mitb_recipient(mode, workdir, careless_user)


def s3_mitb_amount(mode, workdir):
    lab, phone = _setup(mode, workdir)
    before = lab.balance(BOB.account)
    run_transfer(lab, phone, attentive_user, BOB.account, AMOUNT, mitb=Mitb(attacker_to=None, attacker_amount=9_000_000))
    return SUCCEEDED if lab.balance(BOB.account) - before == 9_000_000 else BLOCKED


def s4_forged_qr(mode, workdir):
    lab, phone = _setup(mode, workdir)
    before = lab.balance(MALLORY.account)
    run_transfer(lab, phone, attentive_user, BOB.account, AMOUNT, mitb=Mitb(forge_qr=True, intended_name=BOB.name))
    return SUCCEEDED if lab.balance(MALLORY.account) > before else BLOCKED


TAMPER = {
    "to": MALLORY.account,
    "to_name": MALLORY.name,
    "amount": 9_999_999,
    "currency": "USD",
    "from": BOB.account,
    "nonce": "A" * 22,
    "exp": None,  # replaced by exp + 1
    "tx_id": None,  # replaced by a fresh uuid
}


def s5_field_tamper(mode, workdir):
    now = 1_800_000_000
    tx = new_tx(ALICE.account, BOB.account, BOB.name, AMOUNT, now=now)
    key = secrets.token_bytes(32)
    sk = generate_p256()
    accepted = 0
    for field, value in TAMPER.items():
        if field == "exp":
            value = tx["exp"] + 1
        elif field == "tx_id":
            value = str(uuid.uuid4())
        tampered = dict(tx, **{field: value})
        if mode == "baseline":
            # A TOTP code never looks at the transaction, so it is valid for `tampered` too.
            accepted += totp_verify(key[:20], totp(key[:20], now), now, None) is not None
        elif mode == "hmac":
            accepted += verify_tx_otp(key, tampered, tx_otp(key, tx))
        else:
            accepted += verify_tx_signature(sk.public_key(), tampered, sign_tx(sk, tx))
    return SUCCEEDED if accepted else BLOCKED


def s6_replay(mode, workdir):
    lab, phone = _setup(mode, workdir)
    first = lab.create_transfer(BOB.account, AMOUNT)
    if mode == "baseline":
        evidence = phone.totp_code()
    elif mode == "hmac":
        evidence = phone.hmac_code(first.qr_payload)
    else:
        evidence = None
    if evidence is None:
        phone.sign_and_send(first.qr_payload)
        evidence = phone.last_signature
    else:
        lab.submit_otp(first.tx_id, evidence)
    assert lab.state(first.tx_id) == "executed"
    before = lab.balance(BOB.account)
    second = lab.create_transfer(BOB.account, AMOUNT)
    for tx_id in (first.tx_id, second.tx_id):
        if mode in SIG_MODES:
            phone.send_signature(tx_id, evidence)
        else:
            lab.submit_otp(tx_id, evidence)
    return SUCCEEDED if lab.balance(BOB.account) > before else BLOCKED


def s7_expired(mode, workdir):
    lab, phone = _setup(mode, workdir)
    pending = lab.create_transfer(BOB.account, AMOUNT)
    lab.clock.advance(121)
    _confirm_with_phone(lab, phone, pending)
    return SUCCEEDED if lab.state(pending.tx_id) == "executed" else BLOCKED


def s8_double_submit(mode, workdir, n: int = 50):
    lab, phone = _setup(mode, workdir)
    pending = lab.create_transfer(BOB.account, AMOUNT)
    user_id = lab.user_id()
    now = lab.clock()
    if mode in SIG_MODES:
        signature = phone.sign(decode_qr_payload(pending.qr_payload))
        call = lambda conn: verify.confirm_signature(conn, lab.settings, phone.device_id, pending.tx_id, signature, now)
    else:
        code = phone.totp_code() if mode == "baseline" else phone.hmac_code(pending.qr_payload)
        call = lambda conn: verify.confirm_otp(conn, lab.settings, user_id, pending.tx_id, code, now)
    before = lab.balance(BOB.account)
    barrier = threading.Barrier(n)
    results = []

    def worker():
        conn = connect(str(lab.db_path))
        try:
            barrier.wait()
            results.append(call(conn))
        finally:
            conn.close()

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    accepted = sum(r is verify.Result.OK for r in results)
    moved = lab.balance(BOB.account) - before
    return BLOCKED if accepted == 1 and moved == AMOUNT else SUCCEEDED


def _wrong_codes(valid: set[str], digits: int, count: int) -> list[str]:
    out, i = [], 0
    while len(out) < count:
        candidate = str(i).zfill(digits)
        if candidate not in valid:
            out.append(candidate)
        i += 1
    return out


def s9_online_guessing(mode, workdir):
    lab, phone = _setup(mode, workdir)
    pending = lab.create_transfer(BOB.account, AMOUNT)
    attempts = lab.settings.max_attempts
    if mode == "baseline":
        step = lab.clock() // 30
        valid = {hotp(phone.k_totp, s, phone.totp_digits) for s in (step - 1, step, step + 1)}
        for guess in _wrong_codes(valid, phone.totp_digits, attempts):
            lab.submit_otp(pending.tx_id, guess)
        lab.submit_otp(pending.tx_id, phone.totp_code())
    elif mode == "hmac":
        correct = phone.hmac_code(pending.qr_payload)
        for guess in _wrong_codes({correct}, phone.otp_digits, attempts):
            lab.submit_otp(pending.tx_id, guess)
        lab.submit_otp(pending.tx_id, correct)
    else:
        for _ in range(attempts):
            phone.send_signature(pending.tx_id, secrets.token_bytes(64))
        phone.sign_and_send(pending.qr_payload)
    return SUCCEEDED if lab.state(pending.tx_id) == "executed" else BLOCKED


def s10_db_leak(mode, workdir):
    lab, _ = _setup(mode, workdir)
    leaked = lab.device_row()  # attacker's read-only copy of the devices table
    before = lab.balance(MALLORY.account)
    # The attacker drives the victim's session (MitB) and never involves the user.
    pending = lab.create_transfer(MALLORY.account, AMOUNT)
    if mode == "baseline":
        lab.submit_otp(pending.tx_id, totp(bytes(leaked["k_totp"]), lab.clock()))
    elif mode == "hmac":
        lab.submit_otp(pending.tx_id, tx_otp(bytes(leaked["k_hmac"]), decode_qr_payload(pending.qr_payload)))
    else:
        # Only the public key leaked; the best the attacker can do is sign with their own key.
        forged = sign_tx(generate_p256(), decode_qr_payload(pending.qr_payload))
        lab.post_signature(leaked["id"], pending.tx_id, b64url_encode(forged))
    return SUCCEEDED if lab.balance(MALLORY.account) > before else BLOCKED


def s11_non_repudiation(mode, workdir):
    lab, phone = _setup(mode, workdir)
    tx_id, state = run_transfer(lab, phone, attentive_user, BOB.account, AMOUNT)
    assert state == "executed"
    row = lab.tx_row(tx_id)
    tx = parse_canonical(bytes(row["canonical"]))
    evidence = bytes(row["evidence"])
    device = lab.device_row()
    if mode in SIG_MODES:
        # A third party needs only the public key, which cannot produce signatures.
        ok = verify_tx_signature(public_key_from_raw(bytes(device["public_key"])), tx, evidence)
        return YES if ok else NO
    if mode == "hmac":
        # The bank holds K_hmac and can compute identical evidence itself.
        return NO if tx_otp(bytes(device["k_hmac"]), tx).encode() == evidence else YES
    return NO  # a TOTP code does not reference the transaction


def s12_canonicalization(mode, workdir):
    if mode == "baseline":
        return NA
    cases = json.loads(VECTORS.read_text())["invalid_qr_payloads"]
    accepted = 0
    for case in cases:
        try:
            decode_qr_payload(case["payload"])
            accepted += 1
        except EncodingError:
            pass
    return SUCCEEDED if accepted else BLOCKED


def _malformed(good: bytes) -> list[str]:
    n = P256_ORDER.to_bytes(32, "big")
    raw = [b"", bytes(64), good[:63], good + b"\x00", raw_to_der(good), n + good[32:], good[:32] + n, bytes(32) + good[32:]]
    return [b64url_encode(s) for s in raw] + ["***", "A"]


MALFORMED_CASES = 10  # len(_malformed(...)): 8 raw variants + 2 invalid base64 strings


def s13_malformed_signature(mode, workdir):
    if mode not in SIG_MODES:
        return NA
    lab, phone = _setup(mode, workdir)
    problems = 0
    for i in range(MALFORMED_CASES):
        pending = lab.create_transfer(BOB.account, 1_000)
        good = phone.sign(decode_qr_payload(pending.qr_payload))
        r = lab.post_signature(phone.device_id, pending.tx_id, _malformed(good)[i])
        problems += r.status_code >= 500 or lab.state(pending.tx_id) == "executed"
    missing = lab.phone_http.post("/api/device/confirm", json={"device_id": phone.device_id})
    problems += missing.status_code >= 500
    return SUCCEEDED if problems else BLOCKED


SCENARIOS = {
    "S1": ("Honest transfer", s1_honest),
    "S2a": ("MitB swaps recipient, attentive user", s2a_mitb_recipient_attentive),
    "S2b": ("MitB swaps recipient, careless user", s2b_mitb_recipient_careless),
    "S3": ("MitB changes amount", s3_mitb_amount),
    "S4": ("MitB forges QR with intended details", s4_forged_qr),
    "S5": ("Tamper each field after code issued", s5_field_tamper),
    "S6": ("Replay code on old and new transaction", s6_replay),
    "S7": ("Confirm after expiry", s7_expired),
    "S8": ("50 concurrent submissions of one code", s8_double_submit),
    "S9": ("3 wrong guesses, then correct code", s9_online_guessing),
    "S10": ("Server DB leak, forge transfer", s10_db_leak),
    "S11": ("Third party can verify evidence", s11_non_repudiation),
    "S12": ("Non-canonical QR payloads", s12_canonicalization),
    "S13": ("Malformed signatures", s13_malformed_signature),
}
```

Ghi chú khi đọc kết quả:
- S8 gọi thẳng `server.verify` bằng 50 luồng, mỗi luồng một kết nối SQLite riêng, để thực sự tạo tranh chấp.
- S13 tạo giao dịch mới cho mỗi chữ ký dị dạng, để cơ chế khóa sau 3 lần thử không che mất việc kiểm tra từng chữ ký.

- [ ] **Step 5: Chạy test**

Run: `pytest tests/evaluation/test_scenarios.py -q`
Expected: 1 + 14 × 4 = 57 test PASS. Nếu ô nào lệch, **không sửa `EXPECTED` cho khớp**; báo cả nhóm, tìm nguyên nhân (lỗi kịch bản hay lỗi server), rồi ghi kết luận vào report.

- [ ] **Step 6: Commit**

```bash
git add evaluation/scenarios.py evaluation/expected.py tests/evaluation/test_scenarios.py
git commit -m "feat(eval): attack scenarios S1-S13 with expected matrix"
```

---

### Task 4: Goals, LaTeX, runner (TV5 + TV6)

**Files:**
- Create: `evaluation/goals.py`, `evaluation/latex.py`, `evaluation/run_scenarios.py`
- Modify: `Makefile`
- Test: `tests/evaluation/test_goals_latex.py`

**Interfaces:**
- Consumes: `SCENARIOS`, `EXPECTED`, `GOOD`, `NA`
- Produces: `GOALS: dict[str, tuple[str, list[str]]]`; `goal_holds(results, mode, ids) -> bool | None`; `scenarios_table(results) -> str`; `goals_table(results) -> str`; `python -m evaluation.run_scenarios` ghi `results/scenarios.csv`, `results/scenarios.tex`, `results/goals.tex`, trả mã 1 nếu lệch kỳ vọng

- [ ] **Step 1: Viết test thất bại**

```python
from evaluation.expected import EXPECTED
from evaluation.goals import GOALS, goal_holds
from evaluation.latex import goals_table, scenarios_table


def test_goals_from_expected_matrix():
    holds = {g: {m: goal_holds(EXPECTED, m, ids) for m in ("baseline", "hmac", "sig", "sig_blind")}
             for g, (_, ids) in GOALS.items()}
    assert holds["G1"] == {"baseline": False, "hmac": True, "sig": True, "sig_blind": True}
    assert holds["G5"] == {"baseline": False, "hmac": False, "sig": True, "sig_blind": True}
    assert holds["G6"] == {"baseline": False, "hmac": False, "sig": True, "sig_blind": True}
    assert holds["G7"] == {"baseline": False, "hmac": True, "sig": True, "sig_blind": False}


def test_latex_tables_render():
    t = scenarios_table(EXPECTED)
    assert r"\begin{tabular}" in t and "S2a" in t and r"sig\_blind" in t and r"\xmark" in t
    g = goals_table(EXPECTED)
    assert "G7" in g and r"\cmark" in g
```

- [ ] **Step 2: Chạy để thấy test thất bại**

Run: `pytest tests/evaluation/test_goals_latex.py -q`
Expected: FAIL với `ModuleNotFoundError`

- [ ] **Step 3: Cài đặt `evaluation/goals.py`**

```python
from .outcomes import GOOD, NA

GOALS = {
    "G1": ("Authorization integrity (code bound to the exact transaction)", ["S4", "S5"]),
    "G2": ("Freshness (no replay, no late use)", ["S6", "S7"]),
    "G3": ("Single use under concurrency", ["S8"]),
    "G4": ("Resistance to online guessing", ["S9"]),
    "G5": ("Resilience to server database leak", ["S10"]),
    "G6": ("Non-repudiation", ["S11"]),
    "G7": ("What you see is what you sign", ["S2a", "S3"]),
}


def goal_holds(results: dict, mode: str, ids: list[str]) -> bool | None:
    values = [results[i][mode] for i in ids if results[i][mode] != NA]
    return all(v in GOOD for v in values) if values else None
```

- [ ] **Step 4: Cài đặt `evaluation/latex.py`**

Report cần `\usepackage{pifont,xcolor,booktabs}` cùng các macro `\cmark`, `\xmark` (đã có trong `report/main.tex`).

```python
from .goals import GOALS, goal_holds
from .outcomes import GOOD, MODES, NA

HEADER = " & ".join(m.replace("_", r"\_") for m in MODES)


def _cell(value: str) -> str:
    if value == NA:
        return "--"
    return r"\cmark" if value in GOOD else r"\xmark"


def scenarios_table(results: dict, titles: dict | None = None) -> str:
    titles = titles or {}
    lines = [r"\begin{tabular}{llcccc}", r"\toprule", rf"ID & Scenario & {HEADER} \\", r"\midrule"]
    for sid, row in results.items():
        cells = " & ".join(_cell(row[m]) for m in MODES)
        lines.append(rf"{sid} & {titles.get(sid, '')} & {cells} \\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def goals_table(results: dict) -> str:
    lines = [r"\begin{tabular}{llcccc}", r"\toprule", rf"Goal & Description & {HEADER} \\", r"\midrule"]
    for gid, (desc, ids) in GOALS.items():
        cells = []
        for m in MODES:
            holds = goal_holds(results, m, ids)
            cells.append("--" if holds is None else (r"\cmark" if holds else r"\xmark"))
        lines.append(rf"{gid} & {desc} & {' & '.join(cells)} \\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"
```

- [ ] **Step 5: Cài đặt `evaluation/run_scenarios.py`**

```python
"""Run every scenario in every mode and write results/. Exit 1 on any mismatch."""
import csv
import sys
import tempfile
from pathlib import Path

from .expected import EXPECTED
from .latex import goals_table, scenarios_table
from .outcomes import MODES
from .scenarios import SCENARIOS

RESULTS = Path(__file__).resolve().parents[1] / "results"


def main() -> int:
    RESULTS.mkdir(exist_ok=True)
    results: dict[str, dict[str, str]] = {}
    mismatches = []
    for sid, (title, fn) in SCENARIOS.items():
        results[sid] = {}
        for mode in MODES:
            with tempfile.TemporaryDirectory() as tmp:
                outcome = fn(mode, Path(tmp))
            results[sid][mode] = outcome
            flag = "" if outcome == EXPECTED[sid][mode] else "   <-- MISMATCH"
            if flag:
                mismatches.append((sid, mode, outcome, EXPECTED[sid][mode]))
            print(f"{sid:4} {mode:10} {outcome:10}{flag}")
    with (RESULTS / "scenarios.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scenario", "title", "mode", "outcome", "expected"])
        for sid, (title, _) in SCENARIOS.items():
            for mode in MODES:
                w.writerow([sid, title, mode, results[sid][mode], EXPECTED[sid][mode]])
    titles = {sid: title for sid, (title, _) in SCENARIOS.items()}
    (RESULTS / "scenarios.tex").write_text(scenarios_table(results, titles))
    (RESULTS / "goals.tex").write_text(goals_table(results))
    for sid, mode, got, want in mismatches:
        print(f"MISMATCH {sid} {mode}: got {got}, expected {want}", file=sys.stderr)
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 6: Thêm target vào `Makefile`** (thụt bằng TAB)

```make
.PHONY: scenarios bench sizes bruteforce eval

scenarios:
	$(PY) -m evaluation.run_scenarios

bench:
	$(PY) -m evaluation.bench

sizes:
	$(PY) -m evaluation.sizes

bruteforce:
	$(PY) -m evaluation.bruteforce

eval: test scenarios bench sizes bruteforce
```

- [ ] **Step 7: Chạy test và runner**

Run: `pytest tests/evaluation/test_goals_latex.py -q && make scenarios`
Expected: test PASS; 56 dòng kết quả không có `MISMATCH`; có `results/scenarios.csv`, `results/scenarios.tex`, `results/goals.tex`

- [ ] **Step 8: Commit**

```bash
git add evaluation/goals.py evaluation/latex.py evaluation/run_scenarios.py tests/evaluation/test_goals_latex.py Makefile results/scenarios.csv results/scenarios.tex results/goals.tex
git commit -m "feat(eval): goal matrix, LaTeX tables and scenario runner"
```

---

### Task 5: Addon mitmproxy cho demo thật (TV5)

**Files:**
- Create: `attacker/mitb_addon.py`, `attacker/README.md`
- Test: `tests/evaluation/test_mitb_addon.py`

**Interfaces:**
- Consumes: định dạng HTML của `confirm.html` (`<div id="qr" data-payload="...">`), JSON của `/api/lookup`
- Produces: `mitmdump -s attacker/mitb_addon.py`; lớp `MitB` với `request(flow)` và `response(flow)`; hàm thuần `rewrite_html(html, attacker_account, attacker_name, original_to, original_name) -> str`

- [ ] **Step 1: Viết test thất bại cho phần logic thuần** (không cần cài mitmproxy)

```python
import importlib.util
import sys
import types
from pathlib import Path

# Stub the mitmproxy module so the pure functions can be imported without it.
sys.modules.setdefault("mitmproxy", types.SimpleNamespace(http=types.SimpleNamespace(HTTPFlow=object)))
spec = importlib.util.spec_from_file_location("mitb_addon", Path(__file__).resolve().parents[2] / "attacker" / "mitb_addon.py")
addon = importlib.util.module_from_spec(spec)
spec.loader.exec_module(addon)


def test_rewrite_html_hides_attacker_details():
    html = '<dd id="to-account">0999888777</dd><dd id="to-name">LE VAN M</dd><div id="qr" data-payload="tba1:AAAA">svg</div>'
    out = addon.rewrite_html(html, "0999888777", "LE VAN M", "0123456789", "TRAN THI B")
    assert "0999888777" not in out and "LE VAN M" not in out
    assert "0123456789" in out and "TRAN THI B" in out
    assert 'data-payload="tba1:AAAA"' in out  # genuine QR left untouched


def test_forge_payload_restores_intended_recipient():
    from tba_core.challenge import new_tx
    from tba_core.encoding import decode_qr_payload, encode_qr_payload
    real = new_tx("0011223344", "0999888777", "LE VAN M", 1000, now=1)
    forged = decode_qr_payload(addon.forge_payload(encode_qr_payload(real), "0123456789", "TRAN THI B"))
    assert forged["to"] == "0123456789" and forged["to_name"] == "TRAN THI B" and forged["tx_id"] == real["tx_id"]
```

- [ ] **Step 2: Chạy để thấy test thất bại**

Run: `pytest tests/evaluation/test_mitb_addon.py -q`
Expected: FAIL vì chưa có `attacker/mitb_addon.py`

- [ ] **Step 3: Cài đặt `attacker/mitb_addon.py`**

```python
"""Man-in-the-browser simulation for the live demo.

Run on the victim laptop:  mitmdump -s attacker/mitb_addon.py --listen-port 8080 --ssl-insecure
Point the victim browser at proxy 127.0.0.1:8080 and trust the mitmproxy CA
(http://mitm.it). This models malware that controls the browser.

Environment:
  MITB_ACCOUNT   attacker account (default 0999888777)
  MITB_NAME      attacker display name (default LE VAN M)
  MITB_FORGE_QR  "1" to also replace the QR with one showing the intended
                 recipient (scenario S4; needs `pipx inject mitmproxy segno`)

Only stdlib (+ optional segno) is used because mitmproxy runs in its own environment.
"""
import base64
import json
import logging
import os
import re

from mitmproxy import http

ATTACKER_ACCOUNT = os.environ.get("MITB_ACCOUNT", "0999888777")
ATTACKER_NAME = os.environ.get("MITB_NAME", "LE VAN M")
FORGE_QR = os.environ.get("MITB_FORGE_QR") == "1"
QR_DIV = re.compile(r'<div id="qr" data-payload="(tba1:[A-Za-z0-9_-]+)">.*?</div>', re.DOTALL)
log = logging.getLogger("mitb")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def forge_payload(payload: str, to: str, to_name: str) -> str:
    tx = json.loads(_b64d(payload[len("tba1:"):]))
    tx["to"], tx["to_name"] = to, to_name
    canonical = json.dumps(tx, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return "tba1:" + _b64e(canonical)


def rewrite_html(html: str, attacker_account: str, attacker_name: str, original_to: str, original_name: str | None) -> str:
    html = html.replace(attacker_account, original_to)
    if original_name:
        html = html.replace(attacker_name, original_name)
    return html


def forge_qr_div(html: str, to: str, to_name: str) -> str:
    match = QR_DIV.search(html)
    if not match:
        return html
    try:
        import segno
    except ImportError:
        log.error("segno is not installed in the mitmproxy environment; QR left untouched")
        return html
    payload = forge_payload(match.group(1), to, to_name)
    svg = segno.make(payload, error="m").svg_inline(scale=4)
    return html[:match.start()] + f'<div id="qr" data-payload="{payload}">{svg}</div>' + html[match.end():]


class MitB:
    def __init__(self):
        self.names: dict[str, str] = {}
        self.original_to: str | None = None

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.method == "POST" and flow.request.path == "/transfer":
            form = flow.request.urlencoded_form
            original = form.get("to")
            if original and original != ATTACKER_ACCOUNT:
                self.original_to = original
                form["to"] = ATTACKER_ACCOUNT
                log.warning("[MitB] recipient %s -> %s", original, ATTACKER_ACCOUNT)

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        if flow.request.path.startswith("/api/lookup") and flow.response.status_code == 200:
            try:
                data = json.loads(flow.response.get_text())
                self.names[data["account"]] = data["name"]
            except (ValueError, KeyError):
                pass
            return
        if not self.original_to or "text/html" not in flow.response.headers.get("content-type", ""):
            return
        html = flow.response.get_text()
        name = self.names.get(self.original_to)
        if FORGE_QR and name:
            html = forge_qr_div(html, self.original_to, name)
        flow.response.set_text(rewrite_html(html, ATTACKER_ACCOUNT, ATTACKER_NAME, self.original_to, name))


addons = [MitB()]
```

- [ ] **Step 4: Chạy test**

Run: `pytest tests/evaluation/test_mitb_addon.py -q`
Expected: PASS

- [ ] **Step 5: Viết `attacker/README.md` (runbook demo, dùng để chụp Hình F4)**

````markdown
# Live MitB demo

Setup (once):
```bash
pipx install mitmproxy
pipx inject mitmproxy segno     # only for MITB_FORGE_QR=1
```

For each mode (`hmac`, `sig`, `sig_blind`, `baseline`):
1. `make run MODE=<mode>` and enroll the phone (Forget device first when switching mode).
2. `mitmdump -s attacker/mitb_addon.py --listen-port 8080 --ssl-insecure`
3. Victim browser: proxy 127.0.0.1:8080, trust the mitmproxy CA from http://mitm.it.
4. Log in as alice, type recipient `0123456789` (wait for "TRAN THI B" to appear), amount `1000000`, Continue.
5. Screenshot the browser confirmation page (shows TRAN THI B) **and** the phone screen:
   - `hmac` / `sig`: phone shows `0999888777 LE VAN M` → press Reject → screenshot.
   - `sig_blind`: phone shows only "Approve pending transaction?" → Approve → browser says "Transfer completed" to TRAN THI B, but mallory's balance increased (log in as mallory to screenshot).
6. Optional S4: restart mitmdump with `MITB_FORGE_QR=1`; the phone now shows TRAN THI B; Approve → bank rejects.

Save screenshots as `results/screens/<mode>_<browser|phone>.png`.
````

- [ ] **Step 6: Diễn tập demo trên máy thật** theo runbook, chụp đủ ảnh cho `hmac`, `sig`, `sig_blind`.
- [ ] **Step 7: Commit**

```bash
git add attacker tests/evaluation/test_mitb_addon.py results/screens
git commit -m "feat(attacker): mitmproxy MitB addon and demo runbook"
```

---

### Task 6: Thí nghiệm brute-force S9 (TV6)

**Files:**
- Create: `evaluation/bruteforce.py`
- Test: `tests/evaluation/test_bruteforce.py`

**Interfaces:**
- Consumes: `tx_otp`, `hotp`, `new_tx`
- Produces: `theory_hmac(digits, attempts=3) -> float`, `theory_totp(digits, attempts=3, window_codes=3) -> float`, `simulate_hmac(digits, trials, attempts=3, seed=0) -> float`, `simulate_totp(digits, trials, attempts=3, seed=0) -> float`, `wilson(hits, n, z=1.96) -> (low, high)`; `python -m evaluation.bruteforce` ghi `results/bruteforce.csv` và `results/bruteforce.pdf`

- [ ] **Step 1: Viết test thất bại**

```python
from evaluation.bruteforce import simulate_hmac, theory_hmac, theory_totp, wilson


def test_theory():
    assert theory_hmac(8) == 3 / 10**8
    assert abs(theory_totp(6) - 9e-6) < 1e-7


def test_simulation_matches_theory_at_low_digits():
    # Keys and nonces are random, so use z=4 (flake rate ~1e-4) rather than the 95% interval.
    p = simulate_hmac(digits=3, trials=20_000, seed=1)
    lo, hi = wilson(round(p * 20_000), 20_000, z=4)
    assert lo <= theory_hmac(3) <= hi
```

- [ ] **Step 2: Chạy để thấy test thất bại**

Run: `pytest tests/evaluation/test_bruteforce.py -q`
Expected: FAIL với `ModuleNotFoundError`

- [ ] **Step 3: Cài đặt `evaluation/bruteforce.py`**

```python
"""Online guessing (S9): empirical success rate at 3-4 digits vs. closed form, extrapolated to 6-8."""
import csv
import math
import random
import secrets
from pathlib import Path

from tba_core.challenge import new_tx
from tba_core.hmac_otp import tx_otp
from tba_core.totp import hotp

RESULTS = Path(__file__).resolve().parents[1] / "results"


def theory_hmac(digits: int, attempts: int = 3) -> float:
    return attempts / 10**digits


def theory_totp(digits: int, attempts: int = 3, window_codes: int = 3) -> float:
    space = 10**digits
    return 1 - math.comb(space - window_codes, attempts) / math.comb(space, attempts)


def wilson(hits: int, n: int, z: float = 1.96) -> tuple[float, float]:
    p = hits / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def simulate_hmac(digits: int, trials: int, attempts: int = 3, seed: int = 0) -> float:
    rng = random.Random(seed)
    key = secrets.token_bytes(32)
    hits = 0
    for _ in range(trials):
        correct = tx_otp(key, new_tx("0011223344", "0123456789", "TRAN THI B", 1000, now=1_800_000_000), digits)
        guesses = rng.sample(range(10**digits), attempts)
        hits += any(str(g).zfill(digits) == correct for g in guesses)
    return hits / trials


def simulate_totp(digits: int, trials: int, attempts: int = 3, seed: int = 0) -> float:
    rng = random.Random(seed)
    key = secrets.token_bytes(20)
    hits = 0
    for _ in range(trials):
        step = rng.randrange(1, 10**9)
        valid = {hotp(key, s, digits) for s in (step - 1, step, step + 1)}
        guesses = rng.sample(range(10**digits), attempts)
        hits += any(str(g).zfill(digits) in valid for g in guesses)
    return hits / trials


def main(trials: int = 100_000) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    RESULTS.mkdir(exist_ok=True)
    rows = []
    for scheme, sim, theory in (("hmac", simulate_hmac, theory_hmac), ("baseline", simulate_totp, theory_totp)):
        for d in (3, 4):
            p = sim(d, trials)
            lo, hi = wilson(round(p * trials), trials)
            rows.append({"scheme": scheme, "digits": d, "trials": trials, "empirical": p,
                         "ci_low": lo, "ci_high": hi, "theory": theory(d)})
        for d in (6, 8):
            rows.append({"scheme": scheme, "digits": d, "trials": 0, "empirical": "",
                         "ci_low": "", "ci_high": "", "theory": theory(d)})
    with (RESULTS / "bruteforce.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    fig, ax = plt.subplots(figsize=(5, 3.2))
    for scheme, marker in (("hmac", "o"), ("baseline", "s")):
        th = [r for r in rows if r["scheme"] == scheme]
        ax.plot([r["digits"] for r in th], [r["theory"] for r in th], marker=marker, linestyle="--", label=f"{scheme} theory")
        emp = [r for r in th if r["trials"]]
        ax.errorbar([r["digits"] for r in emp], [r["empirical"] for r in emp],
                    yerr=[[r["empirical"] - r["ci_low"] for r in emp], [r["ci_high"] - r["empirical"] for r in emp]],
                    fmt=marker, capsize=3, label=f"{scheme} measured (95% CI)")
    ax.set_yscale("log")
    ax.set_xlabel("OTP digits")
    ax.set_ylabel("P(success) with 3 guesses")
    ax.legend(fontsize=7)
    fig.tight_layout()
    fig.savefig(RESULTS / "bruteforce.pdf")
    for r in rows:
        print(r)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Chạy test và thí nghiệm**

Run: `pytest tests/evaluation/test_bruteforce.py -q && make bruteforce`
Expected: test PASS; có `results/bruteforce.csv` và `results/bruteforce.pdf`. Thông thường khoảng tin cậy 95% chứa giá trị lý thuyết; theo định nghĩa, khoảng 1/20 lần chạy sẽ không chứa. Nếu gặp trường hợp đó, giữ nguyên số liệu và ghi chú trong report, không chạy lại để chọn kết quả đẹp.

- [ ] **Step 5: Commit**

```bash
git add evaluation/bruteforce.py tests/evaluation/test_bruteforce.py results/bruteforce.csv
git commit -m "feat(eval): online guessing experiment"
```

---

### Task 7: Benchmark P1 và kích thước P3 (TV2)

**Files:**
- Create: `evaluation/bench.py`, `evaluation/sizes.py`
- Test: `tests/evaluation/test_bench.py`

**Interfaces:**
- Produces: `time_op(fn, n) -> (median_us, p95_us)`; `operations() -> dict[str, Callable]`; `python -m evaluation.bench` ghi `results/bench.csv`, `results/bench_env.json`, `results/bench.pdf`; `python -m evaluation.sizes` ghi `results/sizes.csv`

- [ ] **Step 1: Viết test thất bại**

```python
from evaluation.bench import operations, time_op
from evaluation.sizes import measure


def test_all_operations_run():
    ops = operations()
    assert {"canonical_encode", "totp", "hmac_otp", "hmac_otp_verify", "ecdsa_p256_sign",
            "ecdsa_p256_verify", "ed25519_sign", "ed25519_verify"} <= set(ops)
    for fn in ops.values():
        fn()


def test_time_op_returns_positive_numbers():
    median, p95 = time_op(lambda: None, 100)
    assert 0 <= median <= p95


def test_sizes():
    rows = dict((r[0], r[1]) for r in measure())
    assert rows["Transaction OTP (digits)"] == 8
    assert rows["ECDSA P-256 signature, raw (bytes)"] == 64
    assert 68 <= rows["ECDSA P-256 signature, DER max (bytes)"] <= 72
    assert rows["QR version (error level M)"] >= 1
```

- [ ] **Step 2: Chạy để thấy test thất bại**

Run: `pytest tests/evaluation/test_bench.py -q`
Expected: FAIL với `ModuleNotFoundError`

- [ ] **Step 3: Cài đặt `evaluation/bench.py`**

```python
"""P1: per-operation latency of the server-side primitives."""
import csv
import json
import platform
import secrets
import statistics
import time
from pathlib import Path

import cryptography

from tba_core.challenge import new_tx
from tba_core.encoding import canonical_bytes
from tba_core.hmac_otp import tx_otp, verify_tx_otp
from tba_core.signature import (
    generate_ed25519,
    generate_p256,
    sign_tx,
    sign_tx_ed25519,
    verify_tx_signature,
    verify_tx_signature_ed25519,
)
from tba_core.totp import totp

RESULTS = Path(__file__).resolve().parents[1] / "results"


def _openssl_version() -> str:
    # The backend module path has moved between cryptography releases.
    try:
        from cryptography.hazmat.backends.openssl.backend import backend
        return backend.openssl_version_text()
    except Exception:
        return "unknown"


def time_op(fn, n: int) -> tuple[float, float]:
    samples = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - t0) / 1000)
    samples.sort()
    return statistics.median(samples), samples[int(0.95 * (n - 1))]


def operations() -> dict:
    tx = new_tx("0011223344", "0123456789", "TRAN THI B", 1_000_000, now=1_800_000_000)
    k20, k32 = secrets.token_bytes(20), secrets.token_bytes(32)
    code = tx_otp(k32, tx)
    p256 = generate_p256()
    p256_sig = sign_tx(p256, tx)
    ed = generate_ed25519()
    ed_sig = sign_tx_ed25519(ed, tx)
    return {
        "canonical_encode": lambda: canonical_bytes(tx),
        "totp": lambda: totp(k20, 1_800_000_000),
        "hmac_otp": lambda: tx_otp(k32, tx),
        "hmac_otp_verify": lambda: verify_tx_otp(k32, tx, code),
        "ecdsa_p256_sign": lambda: sign_tx(p256, tx),
        "ecdsa_p256_verify": lambda: verify_tx_signature(p256.public_key(), tx, p256_sig),
        "ed25519_sign": lambda: sign_tx_ed25519(ed, tx),
        "ed25519_verify": lambda: verify_tx_signature_ed25519(ed.public_key(), tx, ed_sig),
    }


def main(n: int = 10_000) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    RESULTS.mkdir(exist_ok=True)
    rows = []
    for name, fn in operations().items():
        for _ in range(200):  # warm-up
            fn()
        median, p95 = time_op(fn, n)
        rows.append({"operation": name, "n": n, "median_us": round(median, 2), "p95_us": round(p95, 2)})
        print(rows[-1])
    with (RESULTS / "bench.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    env = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "openssl": _openssl_version(),
    }
    (RESULTS / "bench_env.json").write_text(json.dumps(env, indent=2) + "\n")

    fig, ax = plt.subplots(figsize=(6, 3.2))
    ax.bar([r["operation"] for r in rows], [r["median_us"] for r in rows])
    ax.set_yscale("log")
    ax.set_ylabel("median latency (µs)")
    ax.tick_params(axis="x", rotation=45, labelsize=7)
    fig.tight_layout()
    fig.savefig(RESULTS / "bench.pdf")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Cài đặt `evaluation/sizes.py`**

```python
"""P3: sizes of codes, signatures and QR payloads."""
import csv
from pathlib import Path

import segno

from tba_core.challenge import new_tx
from tba_core.encoding import canonical_bytes, encode_qr_payload
from tba_core.signature import generate_p256, raw_to_der, sign_tx

RESULTS = Path(__file__).resolve().parents[1] / "results"


def measure(samples: int = 1000) -> list[tuple[str, int]]:
    tx = new_tx("0011223344", "0123456789", "TRAN THI B", 1_000_000, now=1_800_000_000)
    sk = generate_p256()
    der = [len(raw_to_der(sign_tx(sk, tx))) for _ in range(samples)]
    payload = encode_qr_payload(tx)
    return [
        ("TOTP code (digits)", 6),
        ("Transaction OTP (digits)", 8),
        ("ECDSA P-256 signature, raw (bytes)", 64),
        ("ECDSA P-256 signature, DER min (bytes)", min(der)),
        ("ECDSA P-256 signature, DER max (bytes)", max(der)),
        ("Ed25519 signature (bytes)", 64),
        ("Canonical transaction (bytes)", len(canonical_bytes(tx))),
        ("QR payload (characters)", len(payload)),
        ("QR version (error level M)", segno.make(payload, error="m").version),
    ]


def main() -> None:
    RESULTS.mkdir(exist_ok=True)
    rows = measure()
    with (RESULTS / "sizes.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["item", "value"])
        w.writerows(rows)
    for r in rows:
        print(r)


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Chạy test và đo**

Run: `pytest tests/evaluation/test_bench.py -q && make bench sizes`
Expected: test PASS; có `results/bench.csv`, `results/bench_env.json`, `results/bench.pdf`, `results/sizes.csv`

Cắm sạc laptop và đóng các ứng dụng nặng trước khi đo; ghi điều kiện đo vào report.

- [ ] **Step 6: Commit**

```bash
git add evaluation/bench.py evaluation/sizes.py tests/evaluation/test_bench.py results/bench.csv results/bench_env.json results/sizes.csv
git commit -m "feat(eval): latency benchmark and size measurements"
```

---

### Task 8: Chạy toàn bộ `make eval` (TV1, mốc M3)

- [ ] **Step 1:** Run: `make eval`
  Expected: mọi test pass, không có `MISMATCH`, đủ các file `results/scenarios.{csv,tex}`, `goals.tex`, `bench.{csv,pdf}`, `bench_env.json`, `sizes.csv`, `bruteforce.{csv,pdf}`.
- [ ] **Step 2:** Run: `make test-js`
  Expected: mọi test pass.
- [ ] **Step 3:** Upload `results/` lên Overleaf; biên dịch report, kiểm tra Bảng T5, T6 và các Hình F5, F6 hiện đúng.
- [ ] **Step 4: Commit**

```bash
git add results
git commit -m "data: full evaluation run for the report"
```

---

### Task 9 (tùy chọn): ProVerif (TV6, chỉ khi dư thời gian sau M2)

**Files:**
- Create: `proverif/tba_sig.pv`, `proverif/tba_sig_blind.pv`, `proverif/README.md`

Mô hình: kênh `c` công khai (trình duyệt và mạng do kẻ tấn công kiểm soát). Người dùng sinh ý định giao dịch mới `ti`, gõ vào trình duyệt (gửi lên `c`), nhận QR `(t, n)` qua `c`, và chỉ ký khi `t = ti` (chế độ `sig`). Ở `sig_blind` người dùng ký mọi `(t, n)`.

- [ ] **Step 1: Viết `proverif/tba_sig.pv`**

```
(* Signature-bound confirmation with trusted display. *)
free c: channel.

type skey.
type pkey.
fun pk(skey): pkey.
fun sign(bitstring, skey): bitstring.
reduc forall m: bitstring, k: skey; checksign(sign(m, k), pk(k)) = m.

event UserIntends(bitstring).
event UserApproves(bitstring, bitstring).
event ServerAccepts(bitstring, bitstring).

query t: bitstring, n: bitstring; event(ServerAccepts(t, n)) ==> event(UserIntends(t)).
query t: bitstring, n: bitstring; inj-event(ServerAccepts(t, n)) ==> inj-event(UserApproves(t, n)).

let User(sk: skey) =
  new ti: bitstring;
  event UserIntends(ti);
  out(c, ti);
  in(c, (t: bitstring, n: bitstring));
  if t = ti then
    event UserApproves(t, n);
    out(c, sign((t, n), sk)).

let Server(pkU: pkey) =
  in(c, t: bitstring);
  new n: bitstring;
  out(c, (t, n));
  in(c, s: bitstring);
  let (=t, =n) = checksign(s, pkU) in
  event ServerAccepts(t, n).

process
  new skU: skey;
  out(c, pk(skU));
  ((!User(skU)) | (!Server(pk(skU))))
```

- [ ] **Step 2: Viết `proverif/tba_sig_blind.pv`**: chép nguyên `tba_sig.pv`, chỉ thay thân `User` thành (bỏ phép so sánh `t = ti`):

```
let User(sk: skey) =
  new ti: bitstring;
  event UserIntends(ti);
  out(c, ti);
  in(c, (t: bitstring, n: bitstring));
  event UserApproves(t, n);
  out(c, sign((t, n), sk)).
```

- [ ] **Step 3: Chạy**

Run: `proverif proverif/tba_sig.pv | grep RESULT && proverif proverif/tba_sig_blind.pv | grep RESULT`
Expected:
- `tba_sig.pv`: cả hai query `is true`.
- `tba_sig_blind.pv`: query `ServerAccepts ==> UserIntends` là `is false` (ProVerif in ra vết tấn công); query `inj-event` vẫn `is true`.

Diễn giải cho report: gắn mật mã cộng nonce đảm bảo server chỉ chấp nhận đúng thứ thiết bị đã duyệt, đúng một lần; nhưng chỉ khi có màn hình tin cậy thì "thứ thiết bị đã duyệt" mới trùng với "thứ người dùng muốn". Nếu kết quả thực tế khác kỳ vọng, ghi nguyên văn output vào report thay vì sửa mô hình cho khớp.

- [ ] **Step 4: Commit**

```bash
git add proverif
git commit -m "feat(formal): optional ProVerif models for sig and sig_blind"
```
