PY ?= python

.PHONY: test vectors

test:
	$(PY) -m pytest -q

vectors:
	$(PY) scripts/gen_vectors.py
