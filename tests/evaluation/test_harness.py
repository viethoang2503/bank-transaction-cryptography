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
