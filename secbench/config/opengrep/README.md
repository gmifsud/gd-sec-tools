# Opengrep rules

`rules/` is a checkout of https://github.com/opengrep/opengrep-rules pinned to the commit in `rules.lock`
(`make prefetch` clones/checks out; never fetched at scan time). It is git-ignored; `rules.lock` is committed.

Pin procedure:

```bash
git clone https://github.com/opengrep/opengrep-rules config/opengrep/rules
git -C config/opengrep/rules log -1 --format=%H          # pick the commit
echo "opengrep-rules@<sha>" > config/opengrep/rules.lock
```

Scope for ISL targets: `csharp/`, `typescript/`, `javascript/`, `dockerfile/`, `yaml/`, `terraform/`, `generic/secrets/`.
To restrict, replace `--config /rules` in `secbench.py::step_opengrep` with multiple `--config /rules/<lang>` args
(kept whole by default so new language packs are picked up on a pin bump).
