# TBA Bank Demo
Midterm project: Transaction-Bound Authentication for Online Banking.
## Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
make test
```
See `docs/architecture.md` and `docs/superpowers/specs/` for the design.

## Run the demo

```bash
make cert            # once; prints the root CA path and the phone URL
make run MODE=hmac   # baseline | hmac | sig | sig_blind
```

Phone setup (once):
- iPhone: AirDrop `rootCA.pem` → Settings → Profile Downloaded → Install → Settings → General → About → Certificate Trust Settings → enable full trust.
- Android: Settings → Security → Encryption & credentials → Install a certificate → CA certificate.

A device can be enrolled only once per account. To enroll again (new phone, or after "Forget this device"), stop the server and run `make reset MODE=<mode>`; this wipes that mode's database.

Then open `https://<LAN-IP>:8443/app/` on the phone and `https://localhost:8443/` on the laptop (log in as `alice` / `alice-pass`).

Fallback if the phone cannot trust the CA: `cloudflared tunnel --url https://localhost:8443 --no-tls-verify` and use the printed `https://*.trycloudflare.com` URL on both devices.
