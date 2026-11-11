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
    ax.set_ylabel("P(success) per transaction, 3 guesses")
    ax.legend(fontsize=7)
    fig.tight_layout()
    fig.savefig(RESULTS / "bruteforce.pdf")
    for r in rows:
        print(r)


if __name__ == "__main__":
    main()
