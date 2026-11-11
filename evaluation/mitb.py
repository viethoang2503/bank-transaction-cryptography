"""Man-in-the-browser model used by automated scenarios.

attacker/mitb_addon.py does the same rewriting on real HTTP traffic.
"""
from dataclasses import dataclass

from tba_core.encoding import decode_qr_payload, encode_qr_payload

from .outcomes import MALLORY


def forge_qr(payload: str, to: str, to_name: str, amount: int) -> str:
    tx = decode_qr_payload(payload)
    tx.update({"to": to, "to_name": to_name, "amount": amount})
    return encode_qr_payload(tx)


@dataclass
class Mitb:
    attacker_to: str | None = MALLORY.account
    attacker_amount: int | None = None
    forge_qr: bool = False
    intended_name: str = ""
    intended_to: str = ""
    intended_amount: int = 0

    def rewrite_request(self, form: dict) -> dict:
        self.intended_to = form["to"]
        self.intended_amount = int(form["amount"])
        out = dict(form)
        if self.attacker_to is not None:
            out["to"] = self.attacker_to
        if self.attacker_amount is not None:
            out["amount"] = str(self.attacker_amount)
        return out

    def rewrite_qr(self, payload: str) -> str:
        if not self.forge_qr:
            return payload
        return forge_qr(payload, self.intended_to, self.intended_name, self.intended_amount)
