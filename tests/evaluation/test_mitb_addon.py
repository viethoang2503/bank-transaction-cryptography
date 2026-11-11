import importlib.util
import sys
import types
from pathlib import Path

# Stub the mitmproxy module so the pure functions can be imported without it.
sys.modules.setdefault("mitmproxy", types.SimpleNamespace(http=types.SimpleNamespace(HTTPFlow=object)))
spec = importlib.util.spec_from_file_location("mitb_addon", Path(__file__).resolve().parents[2] / "attacker" / "mitb_addon.py")
addon = importlib.util.module_from_spec(spec)
spec.loader.exec_module(addon)


def test_rewrite_html_hides_attacker_details():
    html = '<dd id="to-account">0999888777</dd><dd id="to-name">LE VAN M</dd><div id="qr" data-payload="tba1:AAAA">svg</div>'
    out = addon.rewrite_html(html, "0999888777", "LE VAN M", "0123456789", "TRAN THI B")
    assert "0999888777" not in out and "LE VAN M" not in out
    assert "0123456789" in out and "TRAN THI B" in out
    assert 'data-payload="tba1:AAAA"' in out  # genuine QR left untouched


def test_forge_payload_restores_intended_recipient():
    from tba_core.challenge import new_tx
    from tba_core.encoding import decode_qr_payload, encode_qr_payload
    real = new_tx("0011223344", "0999888777", "LE VAN M", 1000, now=1)
    forged = decode_qr_payload(addon.forge_payload(encode_qr_payload(real), "0123456789", "TRAN THI B"))
    assert forged["to"] == "0123456789" and forged["to_name"] == "TRAN THI B" and forged["tx_id"] == real["tx_id"]
