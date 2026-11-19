# CodeGuard Architecture

CodeGuard is built on a **stdlib-first, modular architecture**: zero third-party runtime dependencies, strict separation of concerns, and guaranteed safety invariants (every proposed fix is verified in an isolated scratch worktree).

---

## 1. High-Level Architecture Diagram

```
+=============================================================================+
|                           1. INTERFACE LAYER                                |
|  CLI (`codeguard review | ui | init`)  <--->  Web Dashboard (`/api/scan`)   |
|  Cloudflare Edge Port (`cloudflare/`)   <--->  Pre-Commit & CI Workflows     |
+=============================================================================+
                                      |
                                      v
+=============================================================================+
|                      2. REASONING & PIPELINE ENGINE                         |
|                                                                             |
|  P0: Repo Planner      -> Discovers tree, risk-ranks files, token budgeting |
|  P1: Line-Level Audit  -> Numbered chunk audit for security & AST flaws     |
|  Grounding Gate        -> Verbatim quote verification (drops hallucinations)|
|  P2: Skeptic Review    -> Adversarial staff engineer pass (refutes false +) |
|  P3: Cross-File & AI   -> Auth lifetime, prompt injection, tool safety      |
|  P4: Test Suite Audit  -> Assertion density & repro test synthesis          |
|  P5: Fix QC Sandbox    -> Isolated patch verification (verify or revert)    |
|  P6: Dual-Engine Score -> 70% LLM Reasoning + 30% Deterministic Evidence    |
+=============================================================================+
            |                                               |
            v                                               v
+===================================+   +===================================+
|   3. DETERMINISTIC STATIC CORE    |   |     4. UNIFIED LLM PROVIDER       |
|  `rules/`     AST & regex checks  |   |  `llm_client.py` Provider-agnostic|
|  `scanner.py` Aggregated rules    |   |  Presets: Ollama, DeepSeek, Qwen  |
|  `deps.py`    Dependency pinning  |   |  GLM-4, Kimi, OpenRouter, Claude  |
|  `testrunner` Sandbox test harness|   |  Token budgeting, hash cache, JSON|
+===================================+   +===================================+
                                      |
                                      v
+=============================================================================+
|                         5. OUTPUT & REPORTING                               |
|  HTML Interactive Audit  |  Markdown PR Comment  |  JSON  |  Unified Patch  |
+=============================================================================+
```

---

## 2. The 4 Simplified Logical Layers

### Layer 1: Interface & Access
- **CLI (`codeguard/cli.py`)**: Subcommands `review`, `ui`, `init`, `serve`, `keys`.
- **Web UI & Server (`codeguard/server.py`, `store.py`, `billing.py`)**: Standalone stdlib HTTP server with sliding-window rate limiting, persistent scanning progress, interactive SVG charts, and live reasoning trace stream.
- **Edge Deployment (`cloudflare/`)**: Serverless client-side unzipped worker for edge environments.

### Layer 2: Reasoning & Orchestration (`codeguard/pipeline.py`)
- **Temp Scratch Workspace**: All audits, edits, and test runs happen in a throwaway copy.
- **Multi-Pass Reasoning**:
  - `planner.py`: P0 repository planning, AST entry-point detection, complexity analysis.
  - `multipass.py`: P1 numbered chunk review, Grounding Gate quote matcher, P2 skeptic review, P3 security suite.
  - `testaudit.py`: P4 test coverage verification.
  - `fixer.py`: P5 deterministic and verified AI patch application.
  - `scoring.py`: P6 composite scorecard calculation.

### Layer 3: Deterministic Analysis Core
- **`rules/python_rules.py`**: High-precision AST rules (PY001 eval injection, SQL injection, mutable defaults, swallowed errors, cyclomatic complexity).
- **`rules/generic.py`**: Secret scanning (SEC001), regex heuristics for JS/TS (JS001, JS002), and inline directive parsing (`# codeguard:ignore`).
- **`testrunner.py`**: Discovers and runs project test suites (pytest, unittest, npm) inside temporary sandboxes.

### Layer 4: Provider-Agnostic Intelligence (`codeguard/llm_client.py`, `codeguard/llm.py`)
- **Dynamic Auto-Discovery**: Probes local Ollama instance and automatically selects available models (`qwen2.5-coder:1.5b`, `qwen2.5-coder:3b`, etc.).
- **Cloud Presets**: Built-in endpoints and models for DeepSeek, Qwen, GLM-4, Kimi, OpenRouter, and Anthropic.
- **Reliability Layer**: SHA-256 hash caching (`.codeguard/cache.json`), exponential backoff retries, robust JSON repair, and hard token budget caps.

---

## 3. Core Safety Guarantees

1. **Verify or Revert**: If an auto-fix causes tests to fail, degrades syntax, or introduces new findings, it is **immediately reverted**.
2. **Grounding Gate**: An LLM finding is rejected unless its cited code quote matches the genuine source file verbatim.
3. **No Workspace Tampering**: Original files are never modified unless the user explicitly passes `--apply`.
4. **Honest Reporting**: If LLM providers are unavailable, CodeGuard transparently reports `PARTIAL (Deterministic Only)` without fabricating reasoning scores.
