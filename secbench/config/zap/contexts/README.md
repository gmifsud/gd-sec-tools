# ZAP contexts

One `<slug>.context` per target (ZAP context XML export — create in ZAP desktop, *File → Export Context*).
Matched by `target_slug` at run time and passed as `-n`.

Minimum content: include regex for the API base (`^https?://staging-api\.isl\.local/.*`), exclude regexes for
`.*/logout.*`, `.*/health.*`, `.*/swagger.*`. **No credentials in the context file** — bearer tokens are injected
from `ZAP_TOKEN` in `.env` via the replacer add-on at run time.

Optional `../openapi/<slug>.json` is used as the spec source when the target cannot serve it (`-t /zap/wrk/openapi.json -O <host>`).
