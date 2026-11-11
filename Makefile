PY ?= python
MODE ?= sig
.PHONY: test vectors cert run reset
test:
	$(PY) -m pytest -q
vectors:
	$(PY) scripts/gen_vectors.py

cert:
	scripts/dev_cert.sh

run:
	TBA_MODE=$(MODE) TBA_DB=tba-$(MODE).sqlite3 uvicorn server.main:app --host 0.0.0.0 --port 8443 --ssl-keyfile certs/key.pem --ssl-certfile certs/cert.pem

# Wipe one mode's demo bank (users, balances, enrolled device). The only way to re-enroll.
reset:
	rm -f tba-$(MODE).sqlite3
