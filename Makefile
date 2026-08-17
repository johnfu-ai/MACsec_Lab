.PHONY: help test generate analyze all verify lab down clean doctor

help:
	@echo "MACsec Lab"
	@echo "  make test       - IEEE GCM-AES vectors + MKA/MACsec round-trip"
	@echo "  make generate   - write reference PCAPs + Markdown field dumps"
	@echo "  make analyze    - re-parse existing captures/"
	@echo "  make all        - test + generate"
	@echo "  make verify     - tests + tshark protocol checks"
	@echo "  make lab        - sudo: netns veth replay + live pcap"
	@echo "  make down       - sudo: remove netns/bridge"
	@echo "  make clean      - remove generated decoded/ and live pcap"

doctor:
	@python3 -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; print('python3+cryptography: ok')"
	@command -v tshark >/dev/null && tshark -v | head -1 || echo "tshark: missing (optional)"
	@command -v tcpdump >/dev/null && echo "tcpdump: ok" || echo "tcpdump: missing (needed for make lab)"

test:
	PYTHONPATH=. python3 -m unittest tests.test_protocol -v

generate:
	bash scripts/generate-learning-artifacts.sh

analyze:
	PYTHONPATH=. python3 -m macsec_lab analyze

all: test generate

verify: test generate
	bash scripts/verify.sh

lab:
	sudo bash scripts/run-lab.sh

down:
	sudo bash scripts/teardown.sh

clean:
	rm -rf captures/decoded captures/live-session.pcap run __pycache__ macsec_lab/__pycache__ tests/__pycache__
