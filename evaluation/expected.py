from .outcomes import BLOCKED, NA, NO, OK, SUCCEEDED, YES

_ALL_BLOCKED = {"baseline": BLOCKED, "hmac": BLOCKED, "sig": BLOCKED, "sig_blind": BLOCKED}

EXPECTED = {
    "S1": {"baseline": OK, "hmac": OK, "sig": OK, "sig_blind": OK},
    "S2a": {"baseline": SUCCEEDED, "hmac": BLOCKED, "sig": BLOCKED, "sig_blind": SUCCEEDED},
    "S2b": {"baseline": SUCCEEDED, "hmac": SUCCEEDED, "sig": SUCCEEDED, "sig_blind": SUCCEEDED},
    "S3": {"baseline": SUCCEEDED, "hmac": BLOCKED, "sig": BLOCKED, "sig_blind": SUCCEEDED},
    "S4": {"baseline": SUCCEEDED, "hmac": BLOCKED, "sig": BLOCKED, "sig_blind": BLOCKED},
    "S5": {"baseline": SUCCEEDED, "hmac": BLOCKED, "sig": BLOCKED, "sig_blind": BLOCKED},
    "S6": dict(_ALL_BLOCKED),
    "S7": dict(_ALL_BLOCKED),
    "S8": dict(_ALL_BLOCKED),
    "S9": dict(_ALL_BLOCKED),
    "S10": {"baseline": SUCCEEDED, "hmac": SUCCEEDED, "sig": BLOCKED, "sig_blind": BLOCKED},
    "S11": {"baseline": NO, "hmac": NO, "sig": YES, "sig_blind": YES},
    "S12": {"baseline": NA, "hmac": BLOCKED, "sig": BLOCKED, "sig_blind": BLOCKED},
    "S13": {"baseline": NA, "hmac": NA, "sig": BLOCKED, "sig_blind": BLOCKED},
}
