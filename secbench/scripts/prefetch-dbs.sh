#!/usr/bin/env bash
# prefetch-dbs.sh — the ONLY networked step for scanners. Everything it fetches lands in cache/ (host dir, rsync-able
# to an air-gapped VM). Scans then run with --network none and --skip-*-update / --offline-scan.
set -euo pipefail
cd "$(dirname "$0")/.."

TRIVY=$(grep -E '^trivy=' images.lock | cut -d= -f2-)
[[ -n "$TRIVY" ]] || { echo "trivy not pinned in images.lock — run make pin" >&2; exit 2; }
mkdir -p cache/trivy
UID_GID="$(id -u):$(id -g)"

run_trivy() {
  docker run --rm --pull never --cap-drop ALL --security-opt no-new-privileges --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=256m --user "$UID_GID" -e HOME=/tmp -e TRIVY_CACHE_DIR=/cache \
    -v "$PWD/cache/trivy:/cache:rw" "$TRIVY" "$@"
}

echo ">> trivy vulnerability DB" >&2
run_trivy image --cache-dir /cache --download-db-only --disable-telemetry --skip-version-check
echo ">> trivy java DB" >&2
run_trivy image --cache-dir /cache --download-java-db-only --disable-telemetry --skip-version-check
echo ">> trivy-checks (misconfiguration policies)" >&2
run_trivy config --cache-dir /cache --download-db-only --disable-telemetry --skip-version-check . 2>/dev/null || \
  echo "   (trivy-checks prefetch flag differs on this version — checks will be fetched on first 'trivy config' run without --skip-check-update; see docs/20-IMPLEMENTATION-PLAN.md Phase 1 verification)" >&2

echo ">> opengrep rules" >&2
RULES_LOCK=config/opengrep/rules.lock
RULES_DIR=config/opengrep/rules
if [[ -f "$RULES_LOCK" ]]; then
  SHA=$(sed -n 's/^opengrep-rules@//p' "$RULES_LOCK")
  if [[ ! -d "$RULES_DIR/.git" ]]; then
    git clone --quiet https://github.com/opengrep/opengrep-rules "$RULES_DIR"
  fi
  if [[ "$SHA" == "REPLACE_WITH_COMMIT_SHA" ]]; then
    echo "   rules.lock not pinned. Current HEAD is $(git -C "$RULES_DIR" rev-parse HEAD)" >&2
    echo "   → write 'opengrep-rules@<sha>' to $RULES_LOCK and re-run" >&2
    exit 3
  fi
  git -C "$RULES_DIR" fetch --quiet origin
  git -C "$RULES_DIR" checkout --quiet "$SHA"
  echo "   opengrep-rules @ $(git -C "$RULES_DIR" rev-parse --short HEAD)" >&2
else
  echo "   $RULES_LOCK missing: clone opengrep-rules into $RULES_DIR, pick a commit, write 'opengrep-rules@<sha>'" >&2
fi

echo ">> cache contents" >&2
du -sh cache/trivy "$RULES_DIR" 2>/dev/null || true
