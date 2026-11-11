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
