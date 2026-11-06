#!/usr/bin/env python3
"""
check_suppressions.py — lint config/suppressions.toml (docs/10-SUPPRESSION-POLICY.md).

Every entry MUST have: id (SUP-nnnn, unique), tool, exactly one selector family in [entries.match],
owner (user@isl), justification (>= 20 chars), status (VEX), created, expires (<= created + max_days, not past),
ticket when status == accepted_risk.

validate(path) -> (errors: list[str], expired: list[str]). Expired entries are not errors (observe mode) but the
generator never emits them and gate mode fails on them.
"""
from __future__ import annotations

import datetime as dt
import re
import sys
import tomllib
from pathlib import Path

TOOLS = {"opengrep", "trivy", "gitleaks", "dependency-track", "zap", "*"}
STATUSES = {"not_affected", "false_positive", "accepted_risk", "fixed_elsewhere"}
SELECTOR_FAMILIES = [
    {"fingerprint"},
    {"rule_id"}, {"rule_id", "path"},
    {"path"},
    {"vuln_id"}, {"vuln_id", "purl"},
    {"zap_rule"},
]
ID_RE = re.compile(r"^SUP-\d{4}$")
OWNER_RE = re.compile(r"^[a-z0-9._-]+@[a-z0-9.-]+$")
MAX_DAYS_DEFAULT = 180


def validate(path: Path, today: dt.date | None = None, max_days: int = MAX_DAYS_DEFAULT) -> tuple[list[str], list[str]]:
    today = today or dt.date.today()
    errors, expired, seen = [], [], set()
    if not Path(path).exists():
        return [], []
    with open(path, "rb") as fh:
        doc = tomllib.load(fh)
    if doc.get("schema") != "secbench/suppressions/v1":
        errors.append("schema must be 'secbench/suppressions/v1'")
    for i, e in enumerate(doc.get("entries", [])):
        tag = e.get("id", f"#{i}")
        if not ID_RE.match(str(e.get("id", ""))):
            errors.append(f"{tag}: id must match SUP-nnnn")
        if e.get("id") in seen:
            errors.append(f"{tag}: duplicate id")
        seen.add(e.get("id"))
        if e.get("tool") not in TOOLS:
            errors.append(f"{tag}: tool must be one of {sorted(TOOLS)}")
        keys = set((e.get("match") or {}).keys())
        if keys not in SELECTOR_FAMILIES:
            errors.append(f"{tag}: match must be exactly one of {SELECTOR_FAMILIES}, got {sorted(keys)}")
        if not OWNER_RE.match(str(e.get("owner", ""))):
            errors.append(f"{tag}: owner must be an identity like name@org")
        if len(str(e.get("justification", ""))) < 20:
            errors.append(f"{tag}: justification must be >= 20 characters and reference evidence")
        if e.get("status") not in STATUSES:
            errors.append(f"{tag}: status must be one of {sorted(STATUSES)}")
        if e.get("status") == "accepted_risk" and not e.get("ticket"):
            errors.append(f"{tag}: accepted_risk requires ticket")
        c, x = e.get("created"), e.get("expires")
        if not isinstance(c, dt.date) or not isinstance(x, dt.date):
            errors.append(f"{tag}: created/expires must be TOML dates (YYYY-MM-DD)")
            continue
        if x <= c:
            errors.append(f"{tag}: expires must be after created")
        if (x - c).days > max_days:
            errors.append(f"{tag}: expiry window {(x - c).days}d exceeds policy max {max_days}d")
        if x < today:
            expired.append(f"{tag} expired {x} (owner {e.get('owner')})")
    return errors, expired


if __name__ == "__main__":
    p = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "config" / "suppressions.toml"
    errs, exp = validate(p)
    for e in errs:
        print(f"ERROR   {e}")
    for e in exp:
        print(f"EXPIRED {e}")
    print(f"{p}: {len(errs)} error(s), {len(exp)} expired")
    sys.exit(1 if errs else 0)
