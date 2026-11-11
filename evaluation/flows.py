from .harness import Lab, Pending
from .outcomes import SIG_MODES


def run_transfer(lab: Lab, phone, user, to: str, amount: int, mitb=None) -> tuple[str, str]:
    pending: Pending = lab.create_transfer(to, amount, mitb)
    intended = {"to": to, "amount": amount}
    if lab.mode == "baseline":
        # The phone shows only a code; the browser shows whatever the MitB wants,
        # so the user's view matches their intent and they always type the code.
        lab.submit_otp(pending.tx_id, phone.totp_code())
    elif user(intended, phone.screen(pending.qr_payload)):
        if lab.mode == "hmac":
            lab.submit_otp(pending.tx_id, phone.hmac_code(pending.qr_payload))
        elif lab.mode in SIG_MODES:
            phone.sign_and_send(pending.qr_payload)
    return pending.tx_id, lab.state(pending.tx_id)
