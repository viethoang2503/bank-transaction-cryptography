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
