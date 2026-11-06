# secbench

Self-hosted, local-first application security workbench — the open-source equivalent of Fortify SCA + WebInspect +
SCA + Audit Workbench + SSC, built from Opengrep, Trivy, Gitleaks, OWASP ZAP, DefectDojo and Dependency-Track.

| Doc | Purpose |
|---|---|
| [docs/00-ARCHITECTURE.md](docs/00-ARCHITECTURE.md) | Two-tier design, data flows, schema/identity model, signed-off decisions D1–D7 |
| [docs/10-SUPPRESSION-POLICY.md](docs/10-SUPPRESSION-POLICY.md) | How findings get suppressed (owner / justification / expiry) |
| [docs/20-IMPLEMENTATION-PLAN.md](docs/20-IMPLEMENTATION-PLAN.md) | Phases 0–4 with verification gates and ⚠ items to confirm |

## Quick start (WSL2 / Linux)

```bash
cp .env.example .env
make pin          # resolve images.src → images.lock (digests), build secbench/opengrep from the verified binary
#   then: clone opengrep-rules into config/opengrep/rules and pin a commit in config/opengrep/rules.lock
make prefetch     # trivy DBs + rules into cache/  (the only networked scanner step)
make check
make scan TARGET_DIR=~/src/backend                 # opengrep + trivy(config, sbom) + gitleaks → out/<slug>/<run_id>/
code ~/src/backend                                 # open merged.sarif with the SARIF Viewer extension
```

Management plane (Phase 2): `make mp-up`, fill `DD_API_KEY` / `DT_API_KEY` in `.env`, then
`make ingest RUN_DIR=out/<slug>/<run_id>` (or scans ingest automatically once keys are present).

Requires: Docker (Desktop with WSL2 integration, or Engine), Python ≥ 3.11 (stdlib only), GNU make (optional).
PowerShell users: `python secbench.py scan --target-dir D:\Repos\Backend` works but see D5 in the architecture doc
for why WSL2 + ext4 is recommended.

## Guarantees

- No `:latest`, ever: `secbench.py` refuses to start unless every image in `images.lock` is digest-pinned and present.
- Scanners run read-only on the source, `cap-drop ALL`, `--network none`, no host env or credential mounts.
- Every run is reproducible from `run.json` (images, rule commit, config hashes, target commit).
- Findings hash identically regardless of machine or checkout path.
