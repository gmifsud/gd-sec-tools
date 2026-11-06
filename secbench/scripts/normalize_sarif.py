#!/usr/bin/env python3
"""
normalize_sarif.py — make SARIF 2.1.0 from any scanner hash identically regardless of where it was run.

Transforms (docs/00-ARCHITECTURE.md §2.3):
  1. artifactLocation.uri  → repo-root-relative, uriBaseId "%SRCROOT%", originalUriBaseIds removed
  2. fingerprints          → {"secbench/v1": …} is the ONLY key (DefectDojo takes the first /vN key as
                             unique_id_from_tool); tool-native fingerprints moved to properties.nativeFingerprints
  3. severity              → rule.properties["security-severity"] always set (0–10); level kept/derived
  4. suppressions          → matching entries from suppressions.toml become result.suppressions[] (kind external);
                             results are never deleted
  5. CWE tags normalised to "CWE-nnn" in rule.properties.tags (DefectDojo parses cwe from these)

Stdlib only. Usable as a module (normalize_file) or CLI:
  normalize_sarif.py IN.sarif OUT.sarif --tool opengrep [--suppressions config/suppressions.toml]
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path

SRCROOT = "%SRCROOT%"
FP_KEY = "secbench/v1"
STRIP_PREFIXES = ("file:///src/", "file://src/", "/src/", "src/", "./", "file:///zap/wrk/")
CWE_RE = re.compile(r"CWE[-_ ]?(\d{1,4})", re.IGNORECASE)

DEFAULT_SEVERITY = {
    # (level, precision) → security-severity. precision: very-high|high|medium|low|unknown
    "error":   {"very-high": 8.5, "high": 7.5, "medium": 6.5, "low": 5.0, "unknown": 7.0},
    "warning": {"very-high": 5.5, "high": 5.0, "medium": 4.5, "low": 4.0, "unknown": 5.0},
    "note":    {"very-high": 2.5, "high": 2.0, "medium": 2.0, "low": 1.0, "unknown": 2.0},
    "none":    {"very-high": 1.0, "high": 1.0, "medium": 1.0, "low": 1.0, "unknown": 1.0},
    "secret_override": 8.5,         # any secret finding regardless of tool level
    "gate_threshold": 7.0,          # >= → counts against the gate
}
INJECTION_CWES = {"77", "78", "89", "94", "502", "611", "918", "1336"}  # +1.0 bump when level=error


# --------------------------------------------------------------------------- #
def rebase_uri(uri: str) -> str:
    u = uri.replace("\\", "/")
    changed = True
    while changed:
        changed = False
        for p in STRIP_PREFIXES:
            if u.startswith(p):
                u = u[len(p):]
                changed = True
    # absolute paths left over (e.g. /home/x/src/repo/foo.cs when a tool ignored --workdir) → keep basename chain
    # after the last "/src/" if present; otherwise strip leading slash so DD never sees machine-specific roots.
    if "/src/" in u:
        u = u.split("/src/", 1)[1]
    return u.lstrip("/")


def norm_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


def cwe_tags(tags: list[str]) -> list[str]:
    out, seen = [], set()
    for t in tags:
        m = CWE_RE.search(t)
        if m:
            tag = f"CWE-{int(m.group(1))}"
            if tag not in seen:
                out.append(tag); seen.add(tag)
    return out


def precision_of(rule: dict) -> str:
    return (rule.get("properties", {}).get("precision") or "unknown").lower()


def rule_index(run: dict) -> dict[str, dict]:
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    return {r.get("id"): r for r in rules if r.get("id")}


def result_level(result: dict, rule: dict | None) -> str:
    lvl = result.get("level")
    if not lvl and rule:
        lvl = rule.get("defaultConfiguration", {}).get("level")
    return lvl or "warning"


def is_secret(tool_key: str, rule_id: str, rule: dict | None) -> bool:
    if tool_key == "gitleaks":
        return True
    tags = [t.lower() for t in (rule or {}).get("properties", {}).get("tags", [])]
    return rule_id.lower().startswith("secret") or any("secret" in t for t in tags) or "AVD-SEC" in rule_id.upper()


def security_severity(tool_key: str, rule_id: str, rule: dict | None, level: str, sev_cfg: dict) -> float:
    if is_secret(tool_key, rule_id, rule):
        return float(sev_cfg.get("secret_override", 8.5))
    # trust a tool-supplied value (Trivy SARIF carries CVSS-derived security-severity)
    props = (rule or {}).get("properties", {})
    if "security-severity" in props:
        try:
            return float(props["security-severity"])
        except (TypeError, ValueError):
            pass
    table = sev_cfg.get(level) or DEFAULT_SEVERITY.get(level) or DEFAULT_SEVERITY["warning"]
    val = float(table.get(precision_of(rule or {}), table.get("unknown", 5.0)))
    if level == "error":
        cwes = {t.split("-")[1] for t in cwe_tags(props.get("tags", []))}
        if cwes & INJECTION_CWES:
            val = min(10.0, val + 1.0)
    return round(val, 1)


# --------------------------------------------------------------------------- #
def fingerprint(tool_name: str, rule_id: str, uri: str, snippet: str, partial_key: str) -> str:
    raw = "|".join([tool_name, rule_id, uri, norm_ws(snippet), partial_key])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def native_partial_key(tool_key: str, result: dict, loc: dict) -> str:
    fps = result.get("fingerprints", {}) or {}
    pfps = result.get("partialFingerprints", {}) or {}
    if tool_key == "opengrep":
        return fps.get("matchBasedId/v1") or ""
    if tool_key == "gitleaks":
        # gitleaks partialFingerprints: commitSha, email, author, date, commitMessage; message has rule+redacted secret
        return "|".join([pfps.get("commitSha", ""), result.get("ruleId", ""), norm_ws(result.get("message", {}).get("text", ""))])
    # trivy / generic: ruleId + uri + startLine (region-based)
    region = loc.get("physicalLocation", {}).get("region", {})
    return f"{result.get('ruleId','')}|{loc.get('physicalLocation',{}).get('artifactLocation',{}).get('uri','')}|{region.get('startLine','')}"


# --------------------------------------------------------------------------- #
def match_suppression(entry: dict, tool_key: str, rule_id: str, uri: str, fp: str) -> bool:
    if entry.get("tool") not in (tool_key.split("-")[0], "*"):
        return False
    m = entry.get("match", {})
    if "fingerprint" in m:
        return m["fingerprint"] == fp
    if "rule_id" in m:
        if m["rule_id"] != rule_id:
            return False
        return fnmatch.fnmatch(uri, m["path"]) if "path" in m else True
    if "path" in m and "rule_id" not in m and "vuln_id" not in m:
        return fnmatch.fnmatch(uri, m["path"])
    if "vuln_id" in m:
        return m["vuln_id"] == rule_id or m["vuln_id"] in rule_id
    return False


def normalize_run(run: dict, tool_key: str, suppressions: list[dict], sev_cfg: dict) -> dict:
    driver = run.setdefault("tool", {}).setdefault("driver", {})
    driver.setdefault("name", tool_key)
    rules = rule_index(run)
    run.pop("originalUriBaseIds", None)
    for art in run.get("artifacts", []) or []:
        if "location" in art and "uri" in art["location"]:
            art["location"] = {"uri": rebase_uri(art["location"]["uri"]), "uriBaseId": SRCROOT}

    stats = {"results": 0, "suppressed": 0, "unsuppressed_at_or_above_threshold": 0, "by_level": {}}
    thr = float(sev_cfg.get("gate_threshold", 7.0))

    # rules: tags + security-severity
    for rid, rule in rules.items():
        props = rule.setdefault("properties", {})
        tags = list(props.get("tags", []) or [])
        for c in cwe_tags(tags):
            if c not in tags:
                tags.append(c)
        props["tags"] = tags
        lvl = rule.get("defaultConfiguration", {}).get("level", "warning")
        props["security-severity"] = str(security_severity(tool_key, rid, rule, lvl, sev_cfg))

    for result in run.get("results", []) or []:
        rid = result.get("ruleId") or ""
        rule = rules.get(rid)
        lvl = result_level(result, rule)
        result["level"] = lvl
        locs = result.get("locations") or [{}]
        snippet = ""
        for loc in locs:
            pl = loc.setdefault("physicalLocation", {})
            al = pl.get("artifactLocation", {})
            if "uri" in al:
                pl["artifactLocation"] = {"uri": rebase_uri(al["uri"]), "uriBaseId": SRCROOT}
            if not snippet:
                snippet = pl.get("region", {}).get("snippet", {}).get("text", "")
        for flow in result.get("codeFlows", []) or []:
            for tf in flow.get("threadFlows", []) or []:
                for step in tf.get("locations", []) or []:
                    al = step.get("location", {}).get("physicalLocation", {}).get("artifactLocation", {})
                    if "uri" in al:
                        al["uri"] = rebase_uri(al["uri"]); al["uriBaseId"] = SRCROOT
        uri = locs[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
        partial = native_partial_key(tool_key, result, locs[0])
        fp = fingerprint(driver["name"], rid, uri, snippet, partial)

        native = {}
        if result.get("fingerprints"):
            native["fingerprints"] = result["fingerprints"]
        if result.get("partialFingerprints"):
            native["partialFingerprints"] = result["partialFingerprints"]
        result["fingerprints"] = {FP_KEY: fp}
        result.pop("partialFingerprints", None)
        props = result.setdefault("properties", {})
        if native:
            props["nativeFingerprints"] = native
        sev = security_severity(tool_key, rid, rule, lvl, sev_cfg)
        props["security-severity"] = str(sev)

        # suppressions (never delete, always annotate)
        sup = [e for e in suppressions if match_suppression(e, tool_key, rid, uri, fp)]
        if sup:
            result["suppressions"] = [{
                "kind": "external", "status": "accepted",
                "justification": e["justification"],
                "properties": {"id": e["id"], "owner": e["owner"], "status": e["status"],
                               "expires": str(e["expires"]), "ticket": e.get("ticket")},
            } for e in sup]
            stats["suppressed"] += 1
        elif sev >= thr:
            stats["unsuppressed_at_or_above_threshold"] += 1
        stats["results"] += 1
        stats["by_level"][lvl] = stats["by_level"].get(lvl, 0) + 1
    return stats


def normalize_doc(doc: dict, tool_key: str, suppressions: list[dict], sev_cfg: dict) -> dict:
    if doc.get("version") != "2.1.0":
        raise ValueError(f"not SARIF 2.1.0 (version={doc.get('version')!r})")
    agg = {"results": 0, "suppressed": 0, "unsuppressed_at_or_above_threshold": 0, "by_level": {}}
    for run in doc.get("runs", []):
        s = normalize_run(run, tool_key, suppressions, sev_cfg)
        for k in ("results", "suppressed", "unsuppressed_at_or_above_threshold"):
            agg[k] += s[k]
        for k, v in s["by_level"].items():
            agg["by_level"][k] = agg["by_level"].get(k, 0) + v
    doc.setdefault("properties", {})["secbench"] = {"normalizer": FP_KEY, "tool_key": tool_key}
    return agg


def normalize_file(src: Path, dst: Path, *, tool_key: str, suppressions: list[dict], severity_cfg: dict) -> dict:
    doc = json.loads(Path(src).read_text(encoding="utf-8"))
    stats = normalize_doc(doc, tool_key, suppressions, severity_cfg)
    Path(dst).write_text(json.dumps(doc, indent=1, sort_keys=True), encoding="utf-8")
    return stats


def load_suppressions(path: Path) -> list[dict]:
    with open(path, "rb") as fh:
        return tomllib.load(fh).get("entries", [])


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("src"); p.add_argument("dst")
    p.add_argument("--tool", required=True, help="opengrep|trivy-config|trivy-image|gitleaks")
    p.add_argument("--suppressions")
    a = p.parse_args(argv)
    sups = load_suppressions(Path(a.suppressions)) if a.suppressions else []
    stats = normalize_file(Path(a.src), Path(a.dst), tool_key=a.tool, suppressions=sups, severity_cfg=DEFAULT_SEVERITY)
    print(json.dumps(stats))
    return 0


if __name__ == "__main__":
    sys.exit(main())
