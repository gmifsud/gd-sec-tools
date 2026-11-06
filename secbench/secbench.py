#!/usr/bin/env python3
"""
secbench — local AppSec workbench orchestrator (Fortify-equivalent, self-hosted).

Design contract (docs/00-ARCHITECTURE.md):
  * stdlib only (Python >= 3.11 for tomllib)
  * every scanner runs in a digest-pinned container, read-only source mount,
    cap-drop ALL, no host env passthrough, --network none unless the step needs it
  * every run is a pure function of (target, commit, images.lock, rules, config)
    and is recorded in out/<slug>/<run_id>/run.json

Usage:
  secbench.py prefetch
  secbench.py scan --target-dir PATH [--target-url URL] [--tools opengrep,trivy,gitleaks,zap]
                   [--image REF] [--mode observe|gate] [--no-ingest] [--slug S] [--branch B]
  secbench.py ingest --run-dir out/<slug>/<run_id>
  secbench.py check                       # validate images.lock + suppressions
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT / "scripts"
CONFIG = ROOT / "config"
CACHE = ROOT / "cache"
OUT = ROOT / "out"
DOCS_RUNS = ROOT / "docs" / "runs"
IMAGES_LOCK = ROOT / "images.lock"

sys.path.insert(0, str(SCRIPTS))
import normalize_sarif  # noqa: E402
import merge_sarif  # noqa: E402
import gen_suppressions  # noqa: E402
import check_suppressions  # noqa: E402
import ingest  # noqa: E402

RUN_SCHEMA = "secbench/run/v1"
TOOLS_ALL = ("opengrep", "trivy", "gitleaks", "zap")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
class SecbenchError(RuntimeError):
    pass


def log(msg: str) -> None:
    print(f"[secbench] {msg}", file=sys.stderr, flush=True)


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def load_config() -> dict:
    with open(CONFIG / "secbench.toml", "rb") as fh:
        return tomllib.load(fh)


def load_images_lock() -> dict[str, str]:
    """images.lock: KEY=ref. ref must be registry/image@sha256:<64hex> or sha256:<64hex> (local build)."""
    if not IMAGES_LOCK.exists():
        raise SecbenchError("images.lock missing — run `make pin` (scripts/pin-images.sh) first")
    refs: dict[str, str] = {}
    pat = re.compile(r"^(?P<key>[a-z0-9-]+)=(?P<ref>(?:[^\s@]+@)?sha256:[0-9a-f]{64})$")
    for line in IMAGES_LOCK.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = pat.match(line)
        if not m:
            raise SecbenchError(f"images.lock: unpinned or malformed entry: {line!r}")
        refs[m["key"]] = m["ref"]
    return refs


def image_present(ref: str) -> bool:
    return subprocess.run(["docker", "image", "inspect", ref], capture_output=True).returncode == 0


def require_image(refs: dict[str, str], key: str) -> str:
    ref = refs.get(key)
    if not ref:
        raise SecbenchError(f"images.lock has no entry for {key}")
    if not image_present(ref):
        raise SecbenchError(f"image {key} ({ref}) not present locally — run `make pin` (pull is never done at scan time)")
    return ref


def git(target: Path, *args: str) -> str | None:
    r = subprocess.run(["git", "-C", str(target), *args], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def host_uid_gid() -> str:
    if hasattr(os, "getuid"):
        return f"{os.getuid()}:{os.getgid()}"
    return "1000:1000"  # Windows-native python: Docker Desktop maps to the WSL default user


def docker_backend_is_desktop() -> bool:
    r = subprocess.run(["docker", "info", "--format", "{{.OperatingSystem}}"], capture_output=True, text=True)
    return "Docker Desktop" in r.stdout


def slugify(s: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s or "target"


def derive_slug(target: Path) -> str:
    remote = git(target, "remote", "get-url", "origin")
    if remote:
        name = remote.rstrip("/").split("/")[-1]
        return slugify(name.removesuffix(".git"))
    return slugify(target.name)


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# hardened docker runner
# --------------------------------------------------------------------------- #
def docker_run(
    image: str,
    args: list[str],
    *,
    mounts: list[tuple[Path, str, str]],  # (host_path, container_path, "ro"|"rw")
    env: dict[str, str] | None = None,
    network: str = "none",
    user: str | None = None,
    workdir: str = "/src",
    tmpfs_size: str = "512m",
    extra: list[str] | None = None,
    timeout: int = 3600,
) -> subprocess.CompletedProcess:
    cmd = [
        "docker", "run", "--rm", "--pull", "never",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--read-only",
        "--tmpfs", f"/tmp:rw,noexec,nosuid,size={tmpfs_size}",
        "--network", network,
        "--workdir", workdir,
        "--user", user or host_uid_gid(),
        "-e", "HOME=/tmp",
    ]
    for k, v in (env or {}).items():
        cmd += ["-e", f"{k}={v}"]
    for host, cont, mode in mounts:
        cmd += ["-v", f"{host.resolve()}:{cont}:{mode}"]
    cmd += extra or []
    cmd += [image, *args]
    log("$ " + " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


# --------------------------------------------------------------------------- #
# scanner steps — each returns (exit_code, artefact_name, stderr_tail)
# --------------------------------------------------------------------------- #
def trivy_common_flags() -> list[str]:
    return [
        "--cache-dir", "/cache",
        "--skip-db-update", "--skip-java-db-update", "--skip-check-update",
        "--offline-scan", "--disable-telemetry", "--skip-version-check",
        "--config", "/cfg/trivy.yaml",
    ]


def step_opengrep(refs, target: Path, run_dir: Path, cfg: dict, sup_dir: Path) -> tuple[int, str, str]:
    image = require_image(refs, "opengrep")
    excludes: list[str] = []
    ex_file = sup_dir / "opengrep-excludes.txt"
    if ex_file.exists():
        for p in ex_file.read_text().splitlines():
            if p.strip():
                excludes += ["--exclude", p.strip()]
    args = [
        "scan", "--config", "/rules", "--sarif", "--output", "/out/opengrep.sarif",
        "--metrics=off", "--quiet", "--timeout", str(cfg["opengrep"].get("rule_timeout_s", 30)),
        "--max-target-bytes", str(cfg["opengrep"].get("max_target_bytes", 1_000_000)),
        *excludes, "/src",
    ]
    r = docker_run(image, args, mounts=[
        (target, "/src", "ro"),
        (CONFIG / "opengrep" / "rules", "/rules", "ro"),
        (run_dir, "/out", "rw"),
    ], tmpfs_size="1g", timeout=cfg["opengrep"].get("timeout_s", 1800))
    return r.returncode, "opengrep.sarif", r.stderr[-2000:]


def step_trivy_config(refs, target: Path, run_dir: Path, cfg: dict, sup_dir: Path) -> tuple[int, str, str]:
    """IaC misconfig + secrets → SARIF (vuln scanner excluded by design D1)."""
    image = require_image(refs, "trivy")
    args = [
        "fs", *trivy_common_flags(),
        "--scanners", "misconfig,secret",
        "--format", "sarif", "--output", "/out/trivy-fs.sarif",
        "--ignorefile", "/sup/.trivyignore.yaml",
        "--exit-code", "0", "/src",
    ]
    r = docker_run(image, args, mounts=[
        (target, "/src", "ro"),
        (CACHE / "trivy", "/cache", "rw"),
        (CONFIG / "trivy", "/cfg", "ro"),
        (sup_dir, "/sup", "ro"),
        (run_dir, "/out", "rw"),
    ], env={"TRIVY_CACHE_DIR": "/cache"}, timeout=cfg["trivy"].get("timeout_s", 1800))
    return r.returncode, "trivy-fs.sarif", r.stderr[-2000:]


def step_trivy_sbom(refs, target: Path, run_dir: Path, cfg: dict, sup_dir: Path) -> tuple[int, str, str]:
    """Dependency inventory + vulns → CycloneDX (consumed by Dependency-Track only)."""
    image = require_image(refs, "trivy")
    args = [
        "fs", *trivy_common_flags(),
        "--scanners", "vuln",
        "--format", "cyclonedx", "--output", "/out/sbom.cdx.json",
        "--vex", "/sup/vex.openvex.json",
        "--exit-code", "0", "/src",
    ]
    r = docker_run(image, args, mounts=[
        (target, "/src", "ro"),
        (CACHE / "trivy", "/cache", "rw"),
        (CONFIG / "trivy", "/cfg", "ro"),
        (sup_dir, "/sup", "ro"),
        (run_dir, "/out", "rw"),
    ], env={"TRIVY_CACHE_DIR": "/cache"}, timeout=cfg["trivy"].get("timeout_s", 1800))
    return r.returncode, "sbom.cdx.json", r.stderr[-2000:]


def step_trivy_image(refs, image_ref: str, run_dir: Path, cfg: dict, sup_dir: Path) -> list[tuple[int, str, str]]:
    """docker save → tar → trivy image --input. Docker socket is never mounted into a scanner."""
    image = require_image(refs, "trivy")
    tar = run_dir / "image.tar"
    log(f"docker save {image_ref} -> {tar.name}")
    with open(tar, "wb") as fh:
        r = subprocess.run(["docker", "save", image_ref], stdout=fh, stderr=subprocess.PIPE, text=True)
    if r.returncode != 0:
        return [(r.returncode, "image.tar", r.stderr[-2000:])]
    results = []
    for fmt, out, scanners in (("sarif", "trivy-image.sarif", "vuln,misconfig,secret"),
                               ("cyclonedx", "image.cdx.json", "vuln")):
        args = ["image", *trivy_common_flags(), "--input", "/out/image.tar",
                "--scanners", scanners, "--format", fmt, "--output", f"/out/{out}",
                "--ignorefile", "/sup/.trivyignore.yaml", "--exit-code", "0"]
        rr = docker_run(image, args, workdir="/out", mounts=[
            (CACHE / "trivy", "/cache", "rw"),
            (CONFIG / "trivy", "/cfg", "ro"),
            (sup_dir, "/sup", "ro"),
            (run_dir, "/out", "rw"),
        ], env={"TRIVY_CACHE_DIR": "/cache"}, timeout=cfg["trivy"].get("timeout_s", 1800))
        results.append((rr.returncode, out, rr.stderr[-2000:]))
    tar.unlink(missing_ok=True)
    return results


def step_gitleaks(refs, target: Path, run_dir: Path, cfg: dict, sup_dir: Path) -> tuple[int, str, str]:
    image = require_image(refs, "gitleaks")
    is_git = (target / ".git").exists()
    mode = "git" if is_git else "dir"
    args = [
        mode, "--config", "/cfg/gitleaks.toml",
        "--report-format", "sarif", "--report-path", "/out/gitleaks.sarif",
        "--gitleaks-ignore-path", "/sup/.gitleaksignore",
        "--redact", "--exit-code", "0", "--no-banner", "/src",
    ]
    r = docker_run(image, args, mounts=[
        (target, "/src", "ro"),
        (CONFIG / "gitleaks", "/cfg", "ro"),
        (sup_dir, "/sup", "ro"),
        (run_dir, "/out", "rw"),
    ], env={  # git refuses repos owned by a different uid; we match uid, this is belt-and-braces
        "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": "*",
    }, tmpfs_size="1g", timeout=cfg["gitleaks"].get("timeout_s", 1800))
    return r.returncode, "gitleaks.sarif", r.stderr[-2000:]


def step_zap(refs, target_url: str, run_dir: Path, cfg: dict, sup_dir: Path, mode: str, slug: str) -> tuple[int, str, str]:
    image = require_image(refs, "zap")
    zcfg = cfg["zap"]
    wrk = run_dir / "zap"
    wrk.mkdir(exist_ok=True)
    # assemble the working dir: rule file (+ generated IGNORE rows), context, optional spec
    rules = (CONFIG / "zap" / "api-scan.conf").read_text()
    extra_ignore = sup_dir / "zap-ignore.conf"
    if extra_ignore.exists():
        rules += "\n" + extra_ignore.read_text()
    (wrk / "api-scan.conf").write_text(rules)
    ctx = CONFIG / "zap" / "contexts" / f"{slug}.context"
    spec = CONFIG / "zap" / "openapi" / f"{slug}.json"
    if ctx.exists():
        shutil.copy(ctx, wrk / "target.context")
    if spec.exists():
        shutil.copy(spec, wrk / "openapi.json")

    network = zcfg.get("network", "auto")
    url = target_url
    extra: list[str] = []
    if network == "auto":
        network = "bridge" if docker_backend_is_desktop() else "host"
    if network == "bridge" and re.match(r"^https?://(localhost|127\.0\.0\.1)", url):
        url = re.sub(r"^(https?://)(localhost|127\.0\.0\.1)", r"\1host.docker.internal", url)
        extra += ["--add-host", "host.docker.internal:host-gateway"]
        log(f"local target rewritten for Docker Desktop: {url}")

    fmt = zcfg.get("format", "openapi")
    target_arg = "/zap/wrk/openapi.json" if (spec.exists() and fmt == "openapi") else url
    args = [
        "zap-api-scan.py", "-t", target_arg, "-f", fmt,
        "-c", "api-scan.conf", "-x", "zap.xml", "-J", "zap.json", "-r", "zap.html",
        "-T", str(zcfg.get("max_minutes", 15)),
    ]
    if spec.exists() and fmt == "openapi":
        args += ["-O", re.sub(r"^https?://", "", url).split("/")[0]]
    if ctx.exists():
        args += ["-n", "/zap/wrk/target.context"]
    if mode == "observe":
        args += ["-I"]  # warnings never affect exit code in observe mode
    if zcfg.get("safe_mode", True):
        args += ["-S"]
    token = os.environ.get("ZAP_TOKEN")
    if token:
        args += ["-z", (
            "-config replacer.full_list(0).description=auth "
            "-config replacer.full_list(0).enabled=true "
            "-config replacer.full_list(0).matchtype=REQ_HEADER "
            "-config replacer.full_list(0).matchstr=Authorization "
            f"-config replacer.full_list(0).replacement=Bearer\\ {token}"
        )]
    r = docker_run(image, args, workdir="/zap/wrk", network=network,
                   mounts=[(wrk, "/zap/wrk", "rw")], tmpfs_size="2g", extra=extra,
                   timeout=(zcfg.get("max_minutes", 15) + 5) * 60)
    for f in ("zap.xml", "zap.json", "zap.html"):
        if (wrk / f).exists():
            shutil.move(wrk / f, run_dir / f)
    return r.returncode, "zap.xml", (r.stdout + r.stderr)[-3000:]


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def cmd_check(_: argparse.Namespace) -> int:
    refs = load_images_lock()
    missing = [k for k, v in refs.items() if not image_present(v)]
    log(f"images.lock: {len(refs)} pinned, {len(missing)} not present locally {missing or ''}")
    errors, expired = check_suppressions.validate(CONFIG / "suppressions.toml")
    for e in errors:
        log(f"suppressions: ERROR {e}")
    for e in expired:
        log(f"suppressions: EXPIRED {e}")
    return 1 if (errors or missing) else 0


def cmd_prefetch(_: argparse.Namespace) -> int:
    r = subprocess.run(["bash", str(SCRIPTS / "prefetch-dbs.sh")])
    return r.returncode


def cmd_scan(a: argparse.Namespace) -> int:
    cfg = load_config()
    refs = load_images_lock()
    tools = [t.strip() for t in a.tools.split(",")] if a.tools else list(cfg["scan"]["default_tools"])
    for t in tools:
        if t not in TOOLS_ALL:
            raise SecbenchError(f"unknown tool {t!r}; valid: {TOOLS_ALL}")
    mode = a.mode or os.environ.get("SECBENCH_MODE") or cfg["scan"].get("mode", "observe")

    target = Path(a.target_dir).resolve() if a.target_dir else None
    if target and not target.is_dir():
        raise SecbenchError(f"target dir not found: {target}")
    if "zap" in tools and not a.target_url:
        raise SecbenchError("--target-url required when zap is selected")
    if not target and not a.image:
        raise SecbenchError("--target-dir or --image required")

    commit = git(target, "rev-parse", "HEAD") if target else None
    branch = a.branch or (git(target, "rev-parse", "--abbrev-ref", "HEAD") if target else None) or "unversioned"
    dirty = bool(git(target, "status", "--porcelain")) if (target and commit) else None
    slug = a.slug or (derive_slug(target) if target else slugify(a.image.split("/")[-1].split("@")[0]))
    run_id = utc_now().strftime("%Y%m%dT%H%M%SZ") + "-" + ((commit or "0000000")[:7])
    run_dir = OUT / slug / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    (CACHE / "trivy").mkdir(parents=True, exist_ok=True)

    # suppressions: validate → generate tool-native files for this run (expired = not emitted)
    errors, expired = check_suppressions.validate(CONFIG / "suppressions.toml")
    if errors:
        raise SecbenchError("suppressions.toml invalid: " + "; ".join(errors))
    sup_dir = run_dir / "suppressions"
    active = gen_suppressions.generate(CONFIG / "suppressions.toml", sup_dir)

    manifest = {
        "schema": RUN_SCHEMA, "run_id": run_id, "started": utc_now().isoformat(),
        "host": {"platform": platform.platform(), "docker_desktop": docker_backend_is_desktop()},
        "target": {"slug": slug, "kind": "git" if commit else ("image" if a.image else "dir"),
                   "path": str(target) if target else None, "image": a.image,
                   "commit": commit, "branch": branch, "dirty": dirty, "url": a.target_url},
        "images": {k: refs[k] for k in refs if k in ("opengrep", "trivy", "gitleaks", "zap")},
        "rules": {
            "opengrep": (CONFIG / "opengrep" / "rules.lock").read_text().strip() if (CONFIG / "opengrep" / "rules.lock").exists() else None,
            "gitleaks_cfg": sha256_file(CONFIG / "gitleaks" / "gitleaks.toml"),
            "trivy_cfg": sha256_file(CONFIG / "trivy" / "trivy.yaml"),
            "suppressions": sha256_file(CONFIG / "suppressions.toml"),
        },
        "mode": mode, "tools": tools, "steps": [],
        "suppressions_active": len(active), "suppressions_expired": expired,
    }
    (run_dir / "run.json").write_text(json.dumps(manifest, indent=2))

    def record(tool: str, rc: int, artefact: str, stderr: str, t0: float) -> None:
        manifest["steps"].append({"tool": tool, "exit": rc, "artefact": artefact,
                                  "duration_s": round(time.time() - t0, 1),
                                  "stderr_tail": stderr if rc != 0 else ""})
        (run_dir / "run.json").write_text(json.dumps(manifest, indent=2))
        log(f"{tool}: exit={rc} artefact={artefact}")

    # --- execute ---------------------------------------------------------- #
    if target:
        if "opengrep" in tools:
            t0 = time.time(); record("opengrep", *step_opengrep(refs, target, run_dir, cfg, sup_dir), t0)
        if "trivy" in tools:
            t0 = time.time(); record("trivy-config", *step_trivy_config(refs, target, run_dir, cfg, sup_dir), t0)
            t0 = time.time(); record("trivy-sbom", *step_trivy_sbom(refs, target, run_dir, cfg, sup_dir), t0)
        if "gitleaks" in tools:
            t0 = time.time(); record("gitleaks", *step_gitleaks(refs, target, run_dir, cfg, sup_dir), t0)
    if a.image and "trivy" in tools:
        t0 = time.time()
        for rc, art, err in step_trivy_image(refs, a.image, run_dir, cfg, sup_dir):
            record("trivy-image", rc, art, err, t0)
    if "zap" in tools:
        t0 = time.time(); record("zap", *step_zap(refs, a.target_url, run_dir, cfg, sup_dir, mode, slug), t0)

    # --- normalise + merge ------------------------------------------------ #
    sarif_map = {  # artefact → DefectDojo test_title
        "opengrep.sarif": "opengrep", "trivy-fs.sarif": "trivy-config",
        "trivy-image.sarif": "trivy-image", "gitleaks.sarif": "gitleaks",
    }
    normalised: list[Path] = []
    summary: dict[str, dict] = {}
    for art, title in sarif_map.items():
        src = run_dir / art
        if not src.exists():
            continue
        dst = run_dir / art.replace(".sarif", ".norm.sarif")
        stats = normalize_sarif.normalize_file(src, dst, tool_key=title, suppressions=active, severity_cfg=cfg["severity"])
        summary[title] = stats
        normalised.append(dst)
    if normalised:
        merge_sarif.merge_files(normalised, run_dir / "merged.sarif")
    manifest["results"] = summary
    manifest["finished"] = utc_now().isoformat()

    # --- gate ------------------------------------------------------------- #
    gate_failed: list[str] = []
    if mode == "gate":
        thr = float(cfg["scan"]["gate_min_security_severity"])
        for title, s in summary.items():
            if s["unsuppressed_at_or_above_threshold"] > 0:
                gate_failed.append(f"{title}: {s['unsuppressed_at_or_above_threshold']} finding(s) >= {thr}")
        if expired:
            gate_failed.append(f"{len(expired)} expired suppression(s)")
        zap_step = next((s for s in manifest["steps"] if s["tool"] == "zap"), None)
        if zap_step and zap_step["exit"] != 0:
            gate_failed.append(f"zap exit {zap_step['exit']} (FAIL rules hit or scan error)")
    manifest["gate"] = {"mode": mode, "failed": gate_failed}

    # --- ingest ----------------------------------------------------------- #
    if not a.no_ingest and (os.environ.get("DD_URL") or os.environ.get("DT_URL")):
        manifest["ingest"] = ingest.ingest_run(run_dir, manifest, normalised, summary)
    else:
        manifest["ingest"] = {"skipped": True}

    (run_dir / "run.json").write_text(json.dumps(manifest, indent=2))
    write_run_note(manifest)
    log(f"run complete: {run_dir}")
    log("open merged.sarif in VS Code (SARIF Viewer) with the target folder as workspace root")
    if gate_failed:
        for g in gate_failed:
            log(f"GATE FAIL: {g}")
        return 1
    return 0


def write_run_note(m: dict) -> None:
    """Dataview-queryable run log note for the Obsidian vault."""
    DOCS_RUNS.mkdir(parents=True, exist_ok=True)
    tot = {k: v.get("results", 0) for k, v in m.get("results", {}).items()}
    fm = {
        "type": "secbench-run", "run_id": m["run_id"], "slug": m["target"]["slug"],
        "branch": m["target"]["branch"], "commit": m["target"]["commit"], "mode": m["mode"],
        "started": m["started"], "finished": m.get("finished"),
        "tools": m["tools"], "gate_failed": len(m.get("gate", {}).get("failed", [])) > 0,
        "findings_total": sum(tot.values()),
    }
    lines = ["---"] + [f"{k}: {json.dumps(v)}" for k, v in fm.items()] + ["---", "",
             f"# secbench run {m['run_id']}", "", "| tool | exit | results | artefact |", "|---|---|---|---|"]
    for s in m["steps"]:
        res = m.get("results", {}).get(s["tool"], {}).get("results", "")
        lines.append(f"| {s['tool']} | {s['exit']} | {res} | `{s['artefact']}` |")
    if m.get("gate", {}).get("failed"):
        lines += ["", "## Gate", *[f"- {g}" for g in m["gate"]["failed"]]]
    (DOCS_RUNS / f"{m['run_id']}.md").write_text("\n".join(lines) + "\n")


def cmd_ingest(a: argparse.Namespace) -> int:
    run_dir = Path(a.run_dir).resolve()
    manifest = json.loads((run_dir / "run.json").read_text())
    normalised = sorted(run_dir.glob("*.norm.sarif"))
    manifest["ingest"] = ingest.ingest_run(run_dir, manifest, normalised, manifest.get("results", {}))
    (run_dir / "run.json").write_text(json.dumps(manifest, indent=2))
    return 0 if not manifest["ingest"].get("errors") else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="secbench", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check").set_defaults(fn=cmd_check)
    sub.add_parser("prefetch").set_defaults(fn=cmd_prefetch)
    s = sub.add_parser("scan")
    s.add_argument("--target-dir")
    s.add_argument("--target-url")
    s.add_argument("--image", help="local OCI image ref to scan via docker save")
    s.add_argument("--tools", help="comma list of opengrep,trivy,gitleaks,zap (default from config)")
    s.add_argument("--mode", choices=["observe", "gate"])
    s.add_argument("--slug")
    s.add_argument("--branch")
    s.add_argument("--no-ingest", action="store_true")
    s.set_defaults(fn=cmd_scan)
    i = sub.add_parser("ingest")
    i.add_argument("--run-dir", required=True)
    i.set_defaults(fn=cmd_ingest)
    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except SecbenchError as e:
        log(f"ERROR: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
