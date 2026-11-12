# Live man-in-the-browser screenshots (Figure F4)

Captured with `attacker/mitb_addon.py` running in mitmdump between a compromised
laptop browser and the server, for a transfer alice meant to send to
**TRAN THI B (0123456789)**. The malware rewrites the recipient to the attacker
**LE VAN M (0999888777)** and masks the bank's confirmation page so the laptop
still shows the intended recipient.

| File | What it shows |
|---|---|
| `hmac_laptop.png` / `sig_laptop.png` / `sig_blind_laptop.png` | Bank confirmation page on the laptop — deceived, shows TRAN THI B / 0123456789. |
| `hmac_phone.png` / `sig_phone.png` | Authenticator reads the QR and shows the **true** recipient 0999888777 / LE VAN M, so an attentive user presses Reject. |
| `sig_blind_phone.png` | Blind mode shows no transaction details, so the user cannot notice the swap and approves the theft. |

These are the same attacks the automated harness checks as scenarios S2a/S2b/S3
(see `results/scenarios.csv`); the screenshots are the human-visible evidence.
