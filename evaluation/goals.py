from .outcomes import GOOD, NA

GOALS = {
    "G1": ("Authorization integrity (code bound to the exact transaction)", ["S4", "S5"]),
    "G2": ("Freshness (no replay, no late use)", ["S6", "S7"]),
    "G3": ("Single use under concurrency", ["S8"]),
    # S9 checks the per-transaction lockout only; there is no per-user limit (see Limitations).
    "G4": ("Guessing limit per transaction", ["S9"]),
    "G5": ("Resilience to server database leak", ["S10"]),
    # S11 shows third-party verifiability only; this is necessary but not sufficient for non-repudiation (spec section 5).
    "G6": ("Verifiable evidence (third party can check)", ["S11"]),
    # Holds for the ideal attentive user only: an upper bound on real users (spec section 6).
    "G7": ("What you see is what you sign (attentive user)", ["S2a", "S3"]),
}


def goal_holds(results: dict, mode: str, ids: list[str]) -> bool | None:
    values = [results[i][mode] for i in ids if results[i][mode] != NA]
    return all(v in GOOD for v in values) if values else None
