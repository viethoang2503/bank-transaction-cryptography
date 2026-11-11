"""User decision models for the confirmation step.

`intended` is what the user meant to do: {"to": ..., "amount": ...}.
`screen` is what the phone shows, or None when it shows nothing.
"""


def attentive_user(intended: dict, screen: dict | None) -> bool:
    if screen is None:  # blind signing: nothing to compare, the user approves
        return True
    return screen["to"] == intended["to"] and screen["amount"] == intended["amount"]


def careless_user(intended: dict, screen: dict | None) -> bool:
    return True
