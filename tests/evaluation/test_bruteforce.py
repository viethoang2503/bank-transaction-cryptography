from evaluation.bruteforce import simulate_hmac, theory_hmac, theory_totp, wilson


def test_theory():
    assert theory_hmac(8) == 3 / 10**8
    assert abs(theory_totp(6) - 9e-6) < 1e-7


def test_simulation_matches_theory_at_low_digits():
    # Keys and nonces are random, so use z=4 (flake rate ~1e-4) rather than the 95% interval.
    p = simulate_hmac(digits=3, trials=20_000, seed=1)
    lo, hi = wilson(round(p * 20_000), 20_000, z=4)
    assert lo <= theory_hmac(3) <= hi
