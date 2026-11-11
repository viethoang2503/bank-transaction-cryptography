"""A scripted authenticator built on tba_core. It behaves like authenticator/js/app.js."""
from tba_core.b64 import b64url_decode, b64url_encode
from tba_core.encoding import decode_qr_payload
from tba_core.hmac_otp import tx_otp
from tba_core.signature import generate_p256, public_key_to_raw, sign_tx
from tba_core.totp import totp


class VirtualPhone:
    def __init__(self, http, mode: str, clock):
        self.http = http
        self.mode = mode
        self.clock = clock
        self._sk = generate_p256()
        self.device_id = None
        self.k_totp = None
        self.k_hmac = None
        self.last_signature = None
        config = http.get("/api/config").json()
        self.otp_digits = config["otp_digits"]
        self.totp_digits = config["totp_digits"]

    def enroll(self, enroll_payload: str) -> None:
        prefix = "tbaenroll1:"
        assert enroll_payload.startswith(prefix), enroll_payload
        r = self.http.post("/api/device/enroll", json={
            "token": enroll_payload[len(prefix):],
            "public_key": b64url_encode(public_key_to_raw(self._sk.public_key())),
        })
        r.raise_for_status()
        data = r.json()
        self.device_id = data["device_id"]
        self.k_totp = b64url_decode(data["k_totp"])
        self.k_hmac = b64url_decode(data["k_hmac"])

    def screen(self, qr_payload: str | None) -> dict | None:
        """What the user sees on the phone: nothing in baseline and sig_blind."""
        if self.mode in ("baseline", "sig_blind") or qr_payload is None:
            return None
        return decode_qr_payload(qr_payload)

    def totp_code(self) -> str:
        return totp(self.k_totp, self.clock(), digits=self.totp_digits)

    def hmac_code(self, qr_payload: str) -> str:
        return tx_otp(self.k_hmac, decode_qr_payload(qr_payload), digits=self.otp_digits)

    def sign(self, tx: dict) -> bytes:
        return sign_tx(self._sk, tx)

    def send_signature(self, tx_id: str, signature: bytes):
        return self.http.post("/api/device/confirm", json={
            "device_id": self.device_id, "tx_id": tx_id, "signature": b64url_encode(signature),
        })

    def sign_and_send(self, qr_payload: str) -> str:
        tx = decode_qr_payload(qr_payload)
        self.last_signature = self.sign(tx)
        return self.send_signature(tx["tx_id"], self.last_signature).json()["result"]
