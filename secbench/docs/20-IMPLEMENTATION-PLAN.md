---
title: secbench — Phased Implementation Plan
type: plan
status: active
project: gd-sec-tools/secbench
created: 2026-11-06
updated: 2026-11-06
owner: GMan
tags: [appsec, secbench, plan]
phase: 1-steel-thread
related: "[[00-ARCHITECTURE]]"
---

# Section 3 — Phased Implementation Plan

Each phase ends with a **verification gate** that must pass before the next phase starts. Items marked ⚠ are
facts asserted in the design that must be confirmed against the pinned tool versions — do not skip them.

## Phase 0 — Bootstrap (≈ 1 h)

| # | Step | Command / artefact | Done when |
|---|------|--------------------|-----------|
| 0.1 | Work from WSL2 (D5). Clone targets to ext4 | `mkdir -p ~/src && git clone … ~/src/backend` | `df -T ~/src` shows ext4, not 9p/drvfs |
| 0.2 | Docker Desktop → Settings → Resources → WSL integration enabled for the distro | `docker info --format '{{.OperatingSystem}}'` | prints *Docker Desktop* |
| 0.3 | `cp .env.example .env`; leave DD/DT keys empty for Phase 1 | | |
| 0.4 | Pin images (resolves tags in `images.src`, builds `secbench/opengrep`, writes `images.lock` + `management-plane/images.env`) | `make pin` | `images.lock` has 10 entries, every one `@sha256:` or `sha256:`; review + commit both files |
| 0.5 | Pin Opengrep rules | `git clone https://github.com/opengrep/opengrep-rules config/opengrep/rules`; write `rules.lock` | `make prefetch` exits 0 |
| 0.6 | Prefetch DBs into `cache/` (only networked scanner step) | `make prefetch` | `du -sh cache/trivy` ≈ 600 MB+ |
| 0.7 | Lint | `make check` | 0 errors |

⚠ 0.4: tags in `images.src` were bumped to current releases on 2026-11-12 (Trivy `0.76.2`, Gitleaks `v8.30.1`, ZAP `2.17.0`, DD `3.5.101`, DT `4.14.6`); re-check if pinning more than a week later. Never pin Trivy `0.69.4`–`0.69.6` (CVE-2026-33634). Opengrep binary SHA-256 in `docker/opengrep/Dockerfile` is for `v1.30.0` `opengrep_manylinux_x86` — re-verify against the release page (and cosign-verify the `.cert`/`.sig` if present) before building.

## Phase 1 — Steel thread: Trivy + Opengrep → SARIF → VS Code (≈ ½ day)

Goal: one local run on the backend repo produces a `merged.sarif` that opens cleanly in VS Code with correct file navigation and taint flows. No management plane yet.

| # | Step | Command | Verification |
|---|------|---------|--------------|
| 1.1 | First scan, SAST + IaC/secrets only | `make scan TARGET_DIR=~/src/backend TOOLS=opengrep,trivy` | exit 0; `out/backend/<run_id>/{opengrep,trivy-fs}.norm.sarif`, `merged.sarif`, `sbom.cdx.json`, `run.json` exist |
| 1.2 | Install *SARIF Viewer* (`MS-SarifVSCode.sarif-viewer`); open `~/src/backend` as workspace; open `merged.sarif` | | Clicking a result opens the correct file/line **without** a "locate file" prompt (`%SRCROOT%` bound to workspace) |
| 1.3 | ⚠ Verify Opengrep taint: pick a rule with `codeFlows` (e.g. `csharp.lang.security.injection.*`) | inspect `opengrep.norm.sarif` | `codeFlows[].threadFlows[].locations[]` present and URIs rebased |
| 1.4 | ⚠ Verify Opengrep cross-file claim (D6) | craft a 2-file source→sink fixture under `tests/fixtures/xfile/` | record result in `docs/00-ARCHITECTURE.md` D6 as *confirmed* / *intra-file only* |
| 1.5 | ⚠ Verify Trivy flags on pinned version: `--disable-telemetry`, `--skip-check-update`, `config --download-db-only` | `docker run --rm <trivy> fs --help \| grep -E 'telemetry\|skip-check'` | adjust `trivy_common_flags()` / `prefetch-dbs.sh` if a flag is absent |
| 1.6 | Determinism check: run 1.1 twice on the same commit | `diff <(jq -S .runs[].results[].fingerprints a/merged.sarif) <(… b/…)` | identical fingerprint sets |
| 1.7 | Path-invariance check: copy repo to a second path, rescan | | identical fingerprint sets (the whole point of §2.3) |
| 1.8 | Fill `config/trivy/trivy.yaml` skip-dirs for the three ISL repos; tune `opengrep` `--config` scope | | runtime < 10 min per repo |

Exit criterion: 1.2, 1.6, 1.7 pass; D6 resolved in the architecture doc.

## Phase 2 — Centralised management: DefectDojo + Dependency-Track (≈ 1 day)

| # | Step | Command | Verification |
|---|------|---------|--------------|
| 2.1 | Secrets | `cp management-plane/*/.env.example → .env`; generate with `secrets.token_urlsafe(48)` | no empty values |
| 2.2 | Bring up both stacks | `make mp-up` | DD `http://127.0.0.1:8080`, DT UI `http://127.0.0.1:8082` reachable; DT apiserver log shows NVD/OSV/EPSS mirror sync started (first sync 30–60 min) |
| 2.3 | API keys → `.env` (`DD_API_KEY`, `DT_API_KEY` — DT: Automation team key with `BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD`, `VIEW_PORTFOLIO`, `VULNERABILITY_ANALYSIS`) | | `make check` still 0 |
| 2.4 | Re-ingest the Phase 1 run without rescanning | `make ingest RUN_DIR=out/backend/<run_id>` | `run.json.ingest.defectdojo.opengrep.test_id` set; DT project `backend:<branch>` exists with components |
| 2.5 | ⚠ **Verify DD SARIF parser behaviour on the pinned image** (D3 / §2.3): (a) `security-severity` honoured over `level`; (b) `unique_id_from_tool` = `fingerprints["secbench/v1"]`; (c) CWE parsed from `CWE-nnn` tag | DD UI → Finding → *Unique ID from tool*, *CWE*, *Severity* | if (b) fails: check whether the parser reads `partialFingerprints` first and swap the key placement in `normalize_sarif.py` (single line) |
| 2.6 | Dedupe proof: run `make scan` + ingest **twice** on the same commit | DD Test → *Reimport history* | 2nd reimport: 0 created, N reactivated/untouched, 0 closed |
| 2.7 | Close-old proof: fix one finding, commit, rescan+ingest | | that finding → *Mitigated* in DD; nothing else changes |
| 2.8 | DT policy: create *secbench-gate* policy — `severity >= CRITICAL` OR `EPSS >= 0.2` → **fail**; licence policy for copyleft in mobile app | DT → Policy Management | policy violations visible on project |
| 2.9 | (2b, optional) `SECBENCH_DT_BRIDGE=1` → FPF export into DD | | DD Test `dependency-track:backend` populated; **no** Trivy CVEs appear anywhere else in DD (D1) |

Exit criterion: 2.5, 2.6, 2.7 pass. Record parser facts in `00-ARCHITECTURE.md` §2.3.

## Phase 3 — Dynamic & secret expansion: Gitleaks + ZAP (≈ 1 day)

| # | Step | Command | Verification |
|---|------|---------|--------------|
| 3.1 | Gitleaks over full history | `make scan TARGET_DIR=~/src/backend TOOLS=gitleaks` | `gitleaks.norm.sarif`; secrets **redacted** in `message.text` (`--redact`); every result `security-severity = 8.5` |
| 3.2 | ⚠ uid handling: gitleaks must not emit *dubious ownership* | check `run.json.steps[].stderr_tail` | empty |
| 3.3 | Suppress one known test-fixture secret via `suppressions.toml` (`tool="gitleaks"`, `match.fingerprint`) | rescan | result carries `suppressions[]`; DD import marks it (verify DD maps SARIF suppressions → `false_p`; if not, filter in ingest — one-line change) |
| 3.4 | ZAP context + rule file for the backend API (staging) | `config/zap/contexts/backend.context`, `ZAP_TOKEN` in `.env` | `make dast TARGET_URL=https://staging-api… TARGET_DIR=~/src/backend` exits 0 (observe) |
| 3.5 | ⚠ ZAP local target on Docker Desktop: `localhost` rewrite + `host.docker.internal` | `make dast TARGET_URL=http://localhost:5000` | ZAP reaches the API (zap.json has > 0 alerts or explicit "0 alerts", not connection errors) |
| 3.6 | ⚠ ZAP running as host uid under `--read-only`/`tmpfs`: if ZAP fails to start, raise `tmpfs_size` or drop `--user` for the ZAP step only (document the exception) | | |
| 3.7 | ZAP → DD | ingest | DD Test `zap-api` with **Endpoints** populated |

Exit criterion: 3.1, 3.5, 3.7 pass.

## Phase 4 — Policy gating & CI portability (≈ ½ day)

| # | Step | Command | Verification |
|---|------|---------|--------------|
| 4.1 | Observe → gate on one repo | `make scan TARGET_DIR=… MODE=gate` | exit 1 with `GATE FAIL:` lines listing tool + count; exit 0 once suppressed/fixed |
| 4.2 | Expiry enforcement | set an entry's `expires` to yesterday | gate fails with *expired suppression*; observe mode only warns |
| 4.3 | Threshold tuning | `config/secbench.toml` `gate_min_security_severity` (7.0 = High+) | agreed with team; recorded in `10-SUPPRESSION-POLICY.md` |
| 4.4 | One-line CI entrypoint (not wired yet): `python3 secbench.py scan --target-dir "$BUILD_SOURCESDIRECTORY" --mode gate --no-ingest` | works unchanged in Azure Pipelines (`ubuntu-latest`, docker available) and GitHub Actions | `images.lock` + `cache/` restored from pipeline cache keyed on `images.lock` hash |
| 4.5 | Publish `merged.sarif` as a pipeline artefact (Azure DevOps *SARIF SAST Scans Tab* extension / GitHub code-scanning upload) | | findings visible in the PR without any Tier 2 dependency |

Exit criterion: 4.1 and 4.4 pass on both platforms.

## Out of scope (explicitly, to prevent BDUF)

- SpotBugs/FindSecBugs (no Java targets). Slot: add `step_spotbugs()` emitting SARIF via the `sarif` SpotBugs plugin; normaliser needs no change.
- DefectDojo ↔ Azure Boards issue sync (DD has a native Azure DevOps integration; enable after Phase 2 stabilises).
- TruffleHog verification mode (D7).
- Auto-remediation / PR bots.
