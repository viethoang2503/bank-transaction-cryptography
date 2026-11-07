import os
from dataclasses import dataclass

MODES = ("baseline", "hmac", "sig", "sig_blind")


@dataclass(frozen=True)
class Settings:
    mode: str
    db_path: str
    otp_digits: int = 8
    totp_digits: int = 6
    max_attempts: int = 3
    tx_ttl: int = 120
    enroll_ttl: int = 300
    session_ttl: int = 3600
    cookie_secure: bool = True

    def __post_init__(self):
        if self.mode not in MODES:
            raise ValueError(f"unknown mode {self.mode!r}; expected one of {MODES}")


def settings_from_env() -> Settings:
    return Settings(mode=os.environ.get("TBA_MODE", "sig"), db_path=os.environ.get("TBA_DB", "tba.sqlite3"))
