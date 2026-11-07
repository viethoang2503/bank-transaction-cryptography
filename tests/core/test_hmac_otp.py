import hashlib
import hmac

import pytest

from tba_core.encoding import HMAC_TAG, tagged_message
from tba_core.hmac_otp import tx_otp, verify_tx_otp
from tba_core.totp import dynamic_truncate
from tests.core.test_encoding import TX

KEY = bytes(range(32))


def test_matches_definition():
    mac = hmac.new(KEY, tagged_message(HMAC_TAG, TX), hashlib.sha256).digest()
    assert tx_otp(KEY, TX) == dynamic_truncate(mac, 8)
    assert len(tx_otp(KEY, TX)) == 8


def test_verify_accepts_correct_code():
    assert verify_tx_otp(KEY, TX, tx_otp(KEY, TX))


@pytest.mark.parametrize("field,value", [("to", "0999888777"), ("amount", 9000000), ("nonce", "A" * 22)])
def test_code_is_bound_to_every_field(field, value):
    code = tx_otp(KEY, TX)
    assert not verify_tx_otp(KEY, dict(TX, **{field: value}), code)


@pytest.mark.parametrize("bad", ["", "1234567", "123456789", "abcdefgh", None])
def test_verify_rejects_malformed(bad):
    assert not verify_tx_otp(KEY, TX, bad)


def test_digits_parameter():
    assert len(tx_otp(KEY, TX, digits=4)) == 4
