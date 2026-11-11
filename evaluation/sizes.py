"""P3: sizes of codes, signatures and QR payloads."""
import csv
from pathlib import Path

import segno

from tba_core.challenge import new_tx
from tba_core.encoding import canonical_bytes, encode_qr_payload
from tba_core.signature import generate_p256, raw_to_der, sign_tx

RESULTS = Path(__file__).resolve().parents[1] / "results"


def measure(samples: int = 1000) -> list[tuple[str, int]]:
    tx = new_tx("0011223344", "0123456789", "TRAN THI B", 1_000_000, now=1_800_000_000)
    sk = generate_p256()
    der = [len(raw_to_der(sign_tx(sk, tx))) for _ in range(samples)]
    payload = encode_qr_payload(tx)
    return [
        ("TOTP code (digits)", 6),
        ("Transaction OTP (digits)", 8),
        ("ECDSA P-256 signature, raw (bytes)", 64),
        ("ECDSA P-256 signature, DER min (bytes)", min(der)),
        ("ECDSA P-256 signature, DER max (bytes)", max(der)),
        ("Ed25519 signature (bytes)", 64),
        ("Canonical transaction (bytes)", len(canonical_bytes(tx))),
        ("QR payload (characters)", len(payload)),
        ("QR version (error level M)", segno.make(payload, error="m").version),
    ]


def main() -> None:
    RESULTS.mkdir(exist_ok=True)
    rows = measure()
    with (RESULTS / "sizes.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["item", "value"])
        w.writerows(rows)
    for r in rows:
        print(r)


if __name__ == "__main__":
    main()
