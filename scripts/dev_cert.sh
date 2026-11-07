#!/usr/bin/env bash
# Create a locally trusted certificate for the demo server with mkcert.
# Usage: scripts/dev_cert.sh <extra-host-or-ip>...
set -euo pipefail
command -v mkcert >/dev/null || { echo "Install mkcert first: brew install mkcert nss"; exit 1; }
mkdir -p certs
mkcert -install
LAN_IP=$(ipconfig getifaddr en0 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')
mkcert -cert-file certs/cert.pem -key-file certs/key.pem localhost 127.0.0.1 ${LAN_IP:+"$LAN_IP"} "$@"
echo "Root CA to install on the phone: $(mkcert -CAROOT)/rootCA.pem"
echo "Server URL for the phone: https://${LAN_IP:-localhost}:8443/app/"
