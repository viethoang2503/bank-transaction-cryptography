import pytest

from tba_core.totp import hotp, totp, totp_verify

RFC_KEY = b"12345678901234567890"

HOTP_VECTORS = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]

TOTP_SHA1_8 = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize("counter,expected", list(enumerate(HOTP_VECTORS)))
def test_hotp_rfc4226(counter, expected):
    assert hotp(RFC_KEY, counter) == expected


@pytest.mark.parametrize("t,expected", TOTP_SHA1_8)
def test_totp_rfc6238(t, expected):
    assert totp(RFC_KEY, t, digits=8) == expected


def test_verify_accepts_window_and_returns_step():
    t = 1_800_000_000
    previous = totp(RFC_KEY, t - 30)
    assert totp_verify(RFC_KEY, previous, t, None) == t // 30 - 1


def test_verify_rejects_reuse_of_step():
    t = 1_800_000_000
    code = totp(RFC_KEY, t)
    step = totp_verify(RFC_KEY, code, t, None)
    assert step == t // 30
    assert totp_verify(RFC_KEY, code, t, last_used_step=step) is None


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "12345a", "１２３４５６", None])
def test_verify_rejects_malformed(bad):
    assert totp_verify(RFC_KEY, bad, 1_800_000_000, None) is None


def test_verify_rejects_outside_window():
    t = 1_800_000_000
    assert totp_verify(RFC_KEY, totp(RFC_KEY, t - 90), t, None) is None
