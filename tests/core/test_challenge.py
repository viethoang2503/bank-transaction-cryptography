from tba_core.challenge import is_expired, new_nonce, new_tx
from tba_core.encoding import canonical_bytes


def test_nonce_is_22_char_base64url_and_unique():
    nonces = {new_nonce() for _ in range(1000)}
    assert len(nonces) == 1000
    assert all(len(n) == 22 for n in nonces)


def test_new_tx_is_valid_and_expires():
    tx = new_tx("0011223344", "0123456789", "TRAN THI B", 1_000_000, now=1_800_000_000)
    canonical_bytes(tx)  # raises if invalid
    assert tx["exp"] == 1_800_000_120
    assert not is_expired(tx, 1_800_000_120)
    assert is_expired(tx, 1_800_000_121)


def test_two_identical_requests_differ():
    a = new_tx("0011223344", "0123456789", "TRAN THI B", 1, now=1)
    b = new_tx("0011223344", "0123456789", "TRAN THI B", 1, now=1)
    assert a["nonce"] != b["nonce"] and a["tx_id"] != b["tx_id"]
