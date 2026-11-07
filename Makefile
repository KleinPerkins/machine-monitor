PYTHON ?= .venv/bin/python

.PHONY: verify verify-shard build
verify:
	$(PYTHON) scripts/verify.py all

verify-shard:
	@test -n "$(SHARD)" || (echo 'Use make verify-shard SHARD=core'; exit 2)
	$(PYTHON) scripts/verify.py $(SHARD)

build:
	$(PYTHON) build_mac_app.py

.PHONY: probe-device
probe-device:
	$(PYTHON) scripts/probe_device.py
