---
title: secbench — Suppression Governance Policy
type: policy
status: active
project: gd-sec-tools/secbench
created: 2026-11-06
updated: 2026-11-06
owner: GMan
tags: [appsec, secbench, policy, vex]
related: "[[00-ARCHITECTURE]]"
---

# Suppression Governance

**Rule:** a finding is suppressed only by an entry in `config/suppressions.toml`. Tool-native ignore files
(`.trivyignore*`, `.gitleaksignore`, `.opengrepignore`/`--exclude`, VEX, ZAP `IGNORE` rows) are **generated per run**
from that file and are never committed into a scanned repository. Inline `# nosemgrep`-style comments in target
repos are not recognised as governance — they will still be reported if the rule fires elsewhere.

## Required fields

| Field | Constraint | Enforced by |
|---|---|---|
| `id` | `SUP-nnnn`, unique | `check_suppressions.py` |
| `tool` | `opengrep` · `trivy` · `gitleaks` · `dependency-track` · `zap` · `*` | ″ |
| `match` | exactly one selector family (see `suppressions.toml` header) | ″ |
| `owner` | `name@org` — a person, not a team | ″ |
| `justification` | ≥ 20 chars; must cite evidence (ADR, code path, ticket) | ″ |
| `status` | `not_affected` · `false_positive` · `accepted_risk` · `fixed_elsewhere` (VEX-aligned) | ″ |
| `created`, `expires` | TOML dates; `expires − created ≤ 180 d`; `expires` in the future | ″ |
| `ticket` | required for `accepted_risk` (`AB#1234` or GitHub issue) | ″ |

## Lifecycle

1. Finding triaged in VS Code (SARIF Viewer) or DefectDojo → decision recorded as an entry in a PR to `gd-sec-tools`.
2. Reviewer checks justification against evidence. PR merged ⇒ suppression active from the next run.
3. `make check` in every run: errors block the run; **expired entries are not emitted** → the finding reappears;
   in gate mode an expired entry fails the run until renewed (new `expires`, re-justified) or removed.
4. Renewal is a new PR; the diff is the audit trail. No entry lives longer than 180 days without a human re-reading it.

## Status → tool mapping

| status | Trivy `.trivyignore.yaml` / OpenVEX | Dependency-Track (CycloneDX VEX) | DefectDojo (SARIF `suppressions[]`) |
|---|---|---|---|
| `not_affected` | ignored / `not_affected` + `vulnerable_code_not_in_execute_path` | `analysis.state=not_affected`, `justification=code_not_reachable` | false positive |
| `false_positive` | ignored / `not_affected` | `false_positive` | false positive |
| `accepted_risk` | ignored / `affected` (statement carries ticket) | `exploitable`, `response=[will_not_fix]` | risk accepted |
| `fixed_elsewhere` | ignored / `fixed` | `resolved` | mitigated |

## Gate threshold

`config/secbench.toml → scan.gate_min_security_severity = 7.0` (DefectDojo *High* and above). Secrets are always
8.5 regardless of tool level: rotation cost dominates and EPSS does not apply.
