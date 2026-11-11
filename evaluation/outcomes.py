from server.auth import DEMO_USERS

MODES = ("baseline", "hmac", "sig", "sig_blind")
SIG_MODES = ("sig", "sig_blind")

OK = "ok"
BLOCKED = "blocked"
SUCCEEDED = "succeeded"
YES = "yes"
NO = "no"
NA = "n/a"
BROKEN = "broken"

GOOD = {OK, BLOCKED, YES}
BAD = {SUCCEEDED, NO, BROKEN}

ALICE, BOB, MALLORY = DEMO_USERS
