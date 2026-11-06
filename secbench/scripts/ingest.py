#!/usr/bin/env python3
"""
ingest.py — push run artefacts to the management plane (stdlib only; urllib + hand-rolled multipart).

  DefectDojo      POST {DD_URL}/api/v2/reimport-scan/     one call per tool (SARIF) + ZAP XML
  Dependency-Track PUT {DT_URL}/api/v1/bom                 CycloneDX, autoCreate; poll /api/v1/bom/token/{token}
                   POST {DT_URL}/api/v1/vex                CycloneDX VEX (generated from suppressions.toml)
  optional bridge  GET  {DT_URL}/api/v1/finding/project/{uuid}/export → DD reimport (scan_type FPF)

Env: DD_URL, DD_API_KEY, DT_URL, DT_API_KEY, SECBENCH_DT_BRIDGE=1 (optional), DD_MIN_SEVERITY (default Info)
CLI: ingest.py --run-dir out/<slug>/<run_id>
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

SARIF_TITLES = {"opengrep.norm.sarif": "opengrep", "trivy-fs.norm.sarif": "trivy-config",
                "trivy-image.norm.sarif": "trivy-image", "gitleaks.norm.sarif": "gitleaks"}
ENGAGEMENT = "secbench"
PRODUCT_TYPE = "secbench"
FPF_SCAN_TYPE = "Dependency Track Finding Packaging Format (FPF) Export"


class ApiError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
def _multipart(fields: dict[str, str], files: dict[str, tuple[str, bytes, str]]) -> tuple[bytes, str]:
    boundary = "----secbench" + uuid.uuid4().hex
    body = bytearray()
    for k, v in fields.items():
        body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n").encode()
    for k, (fname, data, ctype) in files.items():
        body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"; filename=\"{fname}\"\r\n"
                 f"Content-Type: {ctype}\r\n\r\n").encode() + data + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def _request(method: str, url: str, headers: dict, data: bytes | None = None, timeout: int = 300) -> dict | list | str:
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        raise ApiError(f"{method} {url} → {e.code}: {e.read()[:500]!r}") from None
    except urllib.error.URLError as e:
        raise ApiError(f"{method} {url} → {e.reason}") from None
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw.decode(errors="replace")


# --------------------------------------------------------------------------- #
class DefectDojo:
    def __init__(self, url: str, key: str):
        self.url = url.rstrip("/"); self.h = {"Authorization": f"Token {key}", "Accept": "application/json"}

    def reimport(self, path: Path, scan_type: str, test_title: str, m: dict, min_sev: str = "Info") -> dict:
        t = m["target"]
        fields = {
            "scan_type": scan_type, "test_title": test_title,
            "product_type_name": PRODUCT_TYPE, "product_name": t["slug"], "engagement_name": ENGAGEMENT,
            "auto_create_context": "true", "deduplication_on_engagement": "true",
            "close_old_findings": "true", "close_old_findings_product_scope": "false",
            "do_not_reactivate": "false", "active": "true", "verified": "false",
            "minimum_severity": min_sev, "scan_date": m["started"][:10],
            "branch_tag": t.get("branch") or "", "commit_hash": t.get("commit") or "",
            "build_id": m["run_id"], "version": t.get("branch") or "",
            "apply_tags_to_findings": "true", "tags": f"secbench,{t.get('branch') or 'unversioned'}",
        }
        ctype = "application/xml" if path.suffix == ".xml" else "application/json"
        body, ct = _multipart(fields, {"file": (path.name, path.read_bytes(), ctype)})
        r = _request("POST", f"{self.url}/api/v2/reimport-scan/", {**self.h, "Content-Type": ct}, body)
        return {"test_id": r.get("test_id") or r.get("test"), "scan_type": scan_type, "title": test_title}


class DependencyTrack:
    def __init__(self, url: str, key: str):
        self.url = url.rstrip("/"); self.h = {"X-Api-Key": key, "Accept": "application/json"}

    def upload_bom(self, path: Path, name: str, version: str) -> dict:
        body, ct = _multipart({"projectName": name, "projectVersion": version, "autoCreate": "true"},
                              {"bom": (path.name, path.read_bytes(), "application/json")})
        r = _request("PUT", f"{self.url}/api/v1/bom", {**self.h, "Content-Type": ct}, body)
        token = r.get("token") if isinstance(r, dict) else None
        deadline = time.time() + 180
        while token and time.time() < deadline:
            st = _request("GET", f"{self.url}/api/v1/bom/token/{token}", self.h)
            if isinstance(st, dict) and not st.get("processing", True):
                break
            time.sleep(3)
        proj = self.lookup(name, version)
        out = {"token": token, "project_uuid": proj.get("uuid") if proj else None}
        if proj:
            metrics = _request("GET", f"{self.url}/api/v1/metrics/project/{proj['uuid']}/current", self.h)
            if isinstance(metrics, dict):
                out["metrics"] = {k: metrics.get(k) for k in ("critical", "high", "medium", "low", "unassigned",
                                                               "vulnerabilities", "policyViolationsTotal", "inheritedRiskScore")}
        return out

    def lookup(self, name: str, version: str) -> dict | None:
        q = urllib.parse.urlencode({"name": name, "version": version})
        r = _request("GET", f"{self.url}/api/v1/project/lookup?{q}", self.h)
        return r if isinstance(r, dict) and r.get("uuid") else None

    def upload_vex(self, path: Path, name: str, version: str) -> dict:
        body, ct = _multipart({"projectName": name, "projectVersion": version},
                              {"vex": (path.name, path.read_bytes(), "application/json")})
        r = _request("POST", f"{self.url}/api/v1/vex", {**self.h, "Content-Type": ct}, body)
        return {"token": r.get("token") if isinstance(r, dict) else None}

    def export_fpf(self, project_uuid: str) -> bytes:
        req = urllib.request.Request(f"{self.url}/api/v1/finding/project/{project_uuid}/export", headers=self.h)
        with urllib.request.urlopen(req, timeout=120) as resp:
            return resp.read()


# --------------------------------------------------------------------------- #
def ingest_run(run_dir: Path, manifest: dict, normalised: list[Path], summary: dict) -> dict:
    out: dict = {"defectdojo": {}, "dependency_track": {}, "errors": []}
    dd = DefectDojo(os.environ["DD_URL"], os.environ["DD_API_KEY"]) if os.environ.get("DD_URL") and os.environ.get("DD_API_KEY") else None
    dt = DependencyTrack(os.environ["DT_URL"], os.environ["DT_API_KEY"]) if os.environ.get("DT_URL") and os.environ.get("DT_API_KEY") else None
    t = manifest["target"]
    version = t.get("branch") or "unversioned"
    min_sev = os.environ.get("DD_MIN_SEVERITY", "Low" if manifest.get("mode") == "gate" else "Info")

    if dd:
        for p in normalised:
            title = SARIF_TITLES.get(p.name, p.stem)
            try:
                out["defectdojo"][title] = dd.reimport(p, "SARIF", title, manifest, min_sev)
                print(f"[ingest] DD {title}: test {out['defectdojo'][title]['test_id']}", file=sys.stderr)
            except ApiError as e:
                out["errors"].append(f"DD {title}: {e}")
        zap = run_dir / "zap.xml"
        if zap.exists():
            try:
                out["defectdojo"]["zap-api"] = dd.reimport(zap, "ZAP Scan", "zap-api", manifest, min_sev)
                print(f"[ingest] DD zap-api: test {out['defectdojo']['zap-api']['test_id']}", file=sys.stderr)
            except ApiError as e:
                out["errors"].append(f"DD zap: {e}")

    if dt:
        for bom in ("sbom.cdx.json", "image.cdx.json"):
            p = run_dir / bom
            if not p.exists():
                continue
            name = t["slug"] if bom == "sbom.cdx.json" else f"{t['slug']}-image"
            try:
                res = dt.upload_bom(p, name, version)
                vex = run_dir / "suppressions" / "vex.cdx.json"
                if vex.exists() and json.loads(vex.read_text()).get("vulnerabilities"):
                    res["vex"] = dt.upload_vex(vex, name, version)
                out["dependency_track"][name] = res
                print(f"[ingest] DT {name}: {res.get('metrics')}", file=sys.stderr)
                if dd and os.environ.get("SECBENCH_DT_BRIDGE") == "1" and res.get("project_uuid"):
                    fpf = run_dir / f"{name}.fpf.json"
                    fpf.write_bytes(dt.export_fpf(res["project_uuid"]))
                    out["defectdojo"][f"dt-{name}"] = dd.reimport(fpf, FPF_SCAN_TYPE, f"dependency-track:{name}", manifest, min_sev)
            except ApiError as e:
                out["errors"].append(f"DT {name}: {e}")

    if not dd and not dt:
        out["skipped"] = "no DD_URL/DD_API_KEY or DT_URL/DT_API_KEY in environment"
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run-dir", required=True)
    a = p.parse_args(argv)
    run_dir = Path(a.run_dir).resolve()
    manifest = json.loads((run_dir / "run.json").read_text())
    res = ingest_run(run_dir, manifest, sorted(run_dir.glob("*.norm.sarif")), manifest.get("results", {}))
    manifest["ingest"] = res
    (run_dir / "run.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps(res, indent=2))
    return 1 if res.get("errors") else 0


if __name__ == "__main__":
    sys.exit(main())
