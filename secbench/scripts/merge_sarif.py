#!/usr/bin/env python3
"""
merge_sarif.py — concatenate normalised SARIF logs into one file for the VS Code SARIF Viewer.

One runs[] entry per tool is preserved (never merged into a single run): both the viewer and DefectDojo key
on tool.driver.name. Ingestion into DefectDojo uses the per-tool *.norm.sarif files, NOT this file (§1.2).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def merge_files(inputs: list[Path], output: Path) -> dict:
    runs, counts = [], {}
    for p in inputs:
        doc = json.loads(Path(p).read_text(encoding="utf-8"))
        for run in doc.get("runs", []):
            runs.append(run)
            name = run.get("tool", {}).get("driver", {}).get("name", "?")
            counts[name] = counts.get(name, 0) + len(run.get("results", []) or [])
    merged = {"$schema": SCHEMA, "version": "2.1.0", "runs": runs,
              "properties": {"secbench": {"merged_from": [Path(p).name for p in inputs]}}}
    Path(output).write_text(json.dumps(merged, indent=1, sort_keys=True), encoding="utf-8")
    return counts


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: merge_sarif.py OUT.sarif IN1.sarif [IN2.sarif ...]", file=sys.stderr); sys.exit(2)
    print(json.dumps(merge_files([Path(x) for x in sys.argv[2:]], Path(sys.argv[1]))))
