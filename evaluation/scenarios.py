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
    # An executed transaction whose stored evidence does not verify is a server bug,
    # never a "good" outcome: report BROKEN instead of YES/NO.
    if mode in SIG_MODES:
        # A third party needs only the public key, which cannot produce signatures.
        ok = verify_tx_signature(public_key_from_raw(bytes(device["public_key"])), tx, evidence)
        return YES if ok else BROKEN
    if mode == "hmac":
        # The bank holds K_hmac and can compute identical evidence itself.
        return NO if tx_otp(bytes(device["k_hmac"]), tx).encode() == evidence else BROKEN
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
