# Live MitB demo

Setup (once):
```bash
pip install -e ".[attack]"      # installs mitmproxy into the project venv
```
Run `mitmdump` from this same venv. The addon needs `segno` (a project dependency)
in the *same* interpreter as mitmproxy for `MITB_FORGE_QR=1`, so a standalone
mitmproxy (e.g. the Homebrew cask) will skip the QR forgery with a logged warning.

For each mode (`hmac`, `sig`, `sig_blind`, `baseline`):
1. `make run MODE=<mode>` and enroll the phone (Forget device first when switching mode; if that mode already has a device, run `make reset MODE=<mode>` before starting the server).
2. `mitmdump -s attacker/mitb_addon.py --listen-port 8080 --ssl-insecure`
3. Victim browser: proxy 127.0.0.1:8080, trust the mitmproxy CA from http://mitm.it.
4. Log in as alice, type recipient `0123456789` (wait for "TRAN THI B" to appear), amount `1000000`, Continue.
5. Screenshot the browser confirmation page (shows TRAN THI B) **and** the phone screen:
   - `hmac` / `sig`: phone shows `0999888777 LE VAN M` → press Reject → screenshot.
   - `sig_blind`: phone shows only "Approve pending transaction?" → Approve → browser says "Transfer completed" to TRAN THI B, but mallory's balance increased (log in as mallory to screenshot).
6. Optional S4: restart mitmdump with `MITB_FORGE_QR=1`; the phone now shows TRAN THI B; Approve → bank rejects.

Save screenshots as `results/screens/<mode>_<browser|phone>.png`.
