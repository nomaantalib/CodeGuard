# Architecture

Goal: keep it **simple and lenient** (stdlib only, one process, SQLite) while staying robust (everything an AI proposes is verified).

```
            +------------------- review(root, cfg, fix, apply) -------------------+
 project -> | 1 collect files   2 static scan (rules + bandit/ruff/pip-audit)     |
            | 3 copy to temp workspace   4 run baseline tests                      |
            | 5 (AI) review riskiest files -> extra findings                       |
            | 6 FIX LOOP per file:                                                 |
            |     deterministic fix per rule -> syntax check -> run tests          |
            |         tests worse than baseline?  -> REVERT that fix               |
            |     (AI) whole-file patch -> syntax, no new findings, tests          |
            | 7 re-scan + re-test fixed copy   8 score before/after + gate         |
            | 9 report (md/html/json) + unified diff patch  10 (--apply) write back|
            +----------------------------------------------------------------------+
```

## Modules
| Module | Responsibility |
|---|---|
| `discovery.py` | walk the tree (ignore dirs, size cap, no symlinks); splits source vs config files |
| `rules/python_rules.py` | AST rules: dangerous calls, SQL injection, hallucinated imports, stubs, complexity |
| `rules/generic.py` | secrets (masked in output), TODO markers, JS/TS regex rules, `codeguard:ignore` |
| `workflow.py`, `deps.py` | project hygiene, GitHub workflow/Dockerfile checks, dependency pinning |
| `external.py` | optional bandit / ruff / pip-audit bridges (JSON in, `Finding` out) |
| `scanner.py` | combines everything; `scan_source()` re-scans one file quickly after each fix |
| `testrunner.py` | pytest / unittest / npm; optional Docker sandbox; strips secret env vars |
| `fixer.py` | deterministic line fixers (+ import insertion after docstring/`__future__`) |
| `llm.py` | Ollama native API (Qwen default), OpenAI-compatible providers and optional Anthropic via urllib; review + fix prompts |
| `pipeline.py` | the orchestration above; owns the verify-or-revert policy |
| `scoring.py` | per-category 0-100, weights security 35 / tests 25 / quality 15 / deps 15 / workflow 10 |
| `report.py` | Markdown (PR comment), HTML (dark/light aware), JSON, patch |
| `server.py`, `store.py`, `billing.py` | multi-tenant API: hashed API keys, monthly quotas, plan features, Stripe webhook |

## Safety model
* **Temp workspace**: all edits and test runs happen in a copy. `--apply` is the only path that writes to your tree.
* **Verify or revert**: syntax check + test regression check per fix; AI patches also must not add findings.
* **Untrusted code**: the server never executes customer tests unless a Docker sandbox exists
  (`--network none`, 1 CPU, 1 GB, no capabilities, non-root). A customer `codeguard.toml` cannot override sandbox settings - server overrides win.
* **Zip uploads**: path traversal, symlinks, zip bombs (size and file-count caps) are rejected.
* **Secrets**: findings never print the secret value; API key is removed from the environment of test runs; API keys are stored as SHA-256 hashes.
* **Prompt injection**: the model only returns text; it has no tools; output is validated before use.
* **Webhooks**: Stripe signatures verified (HMAC-SHA256, 5-minute replay window).

## Extending
* **New rule**: add an entry to `rules/catalog.py`, emit it with `mk(...)` in `python_rules.py` or `generic.py`, add a test in `tests/test_rules.py`.
* **New auto-fix**: add a line transform to `fixer.LINE_FIXERS` and set `fixable=True` on the finding. The pipeline verifies it automatically.
* **New language**: add a `scan_<lang>()` returning `Finding`s and call it from `scanner.scan_source`; add a test command in `testrunner.py`.
* **Other LLM providers**: subclass/replace `LLM.complete()` - everything else is provider-agnostic. `CODEGUARD_LLM_URL` points at a compatible endpoint.
* **Bigger scale**: swap the thread pool for a queue (Redis/SQS) + worker containers; SQLite for Postgres (`store.py` is the only SQL).
