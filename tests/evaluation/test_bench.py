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
