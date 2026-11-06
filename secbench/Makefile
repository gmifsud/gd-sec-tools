# secbench — thin shim over secbench.py (the engine). Works from WSL2/Linux; PowerShell users call python directly.
PY        ?= python3
TARGET_DIR ?=
TARGET_URL ?=
IMAGE      ?=
TOOLS      ?=
MODE       ?= observe
MP         := management-plane

-include .env
export

.PHONY: help pin prefetch check scan scan-image dast ingest mp-up mp-down mp-logs clean

help:
	@echo "make pin                         resolve images.src tags -> images.lock digests, build opengrep image"
	@echo "make prefetch                    pull trivy-db/java-db/checks + opengrep rules into cache/ (only networked step)"
	@echo "make check                       validate images.lock presence + suppressions.toml"
	@echo "make scan TARGET_DIR=~/src/x [TOOLS=opengrep,trivy,gitleaks] [MODE=observe|gate]"
	@echo "make scan-image IMAGE=acr.io/app:tag"
	@echo "make dast TARGET_URL=http://localhost:5000 [TARGET_DIR=...]"
	@echo "make ingest RUN_DIR=out/<slug>/<run_id>"
	@echo "make mp-up | mp-down | mp-logs   DefectDojo + Dependency-Track compose stacks"

pin:
	bash scripts/pin-images.sh

prefetch:
	$(PY) secbench.py prefetch

check:
	$(PY) secbench.py check

scan:
	@test -n "$(TARGET_DIR)" || { echo "TARGET_DIR required"; exit 2; }
	$(PY) secbench.py scan --target-dir "$(TARGET_DIR)" --mode $(MODE) $(if $(TOOLS),--tools $(TOOLS),) $(if $(TARGET_URL),--target-url "$(TARGET_URL)",)

scan-image:
	@test -n "$(IMAGE)" || { echo "IMAGE required"; exit 2; }
	$(PY) secbench.py scan --image "$(IMAGE)" --tools trivy --mode $(MODE)

dast:
	@test -n "$(TARGET_URL)" || { echo "TARGET_URL required"; exit 2; }
	$(PY) secbench.py scan $(if $(TARGET_DIR),--target-dir "$(TARGET_DIR)",--slug dast) --target-url "$(TARGET_URL)" --tools zap --mode $(MODE)

ingest:
	@test -n "$(RUN_DIR)" || { echo "RUN_DIR required"; exit 2; }
	$(PY) secbench.py ingest --run-dir "$(RUN_DIR)"

mp-up:
	docker compose --env-file $(MP)/images.env --env-file $(MP)/defectdojo/.env -f $(MP)/defectdojo/docker-compose.yml up -d
	docker compose --env-file $(MP)/images.env --env-file $(MP)/dependency-track/.env -f $(MP)/dependency-track/docker-compose.yml up -d

mp-down:
	docker compose --env-file $(MP)/images.env --env-file $(MP)/defectdojo/.env -f $(MP)/defectdojo/docker-compose.yml down
	docker compose --env-file $(MP)/images.env --env-file $(MP)/dependency-track/.env -f $(MP)/dependency-track/docker-compose.yml down

mp-logs:
	docker compose --env-file $(MP)/images.env --env-file $(MP)/defectdojo/.env -f $(MP)/defectdojo/docker-compose.yml logs -f --tail 100

clean:
	rm -rf out/*
