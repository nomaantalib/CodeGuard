# 🛡️ CodeGuard — AI Code Review & Security Audit Agent

**Review before you deploy.**

CodeGuard is a local-first code review agent. Point it at a project folder and it checks the code for selected security risks and quality problems, runs available tests, asks an AI model to review suspicious code, and creates an audit report.

It is designed to be an **extra reviewer** for code written by people or AI coding tools. It does not replace a developer, a professional security audit, or a complete test strategy.

> **In simple words:** Your coding tool writes the code. CodeGuard checks it again and tells you what may be wrong.

---

## 1. What problem does CodeGuard solve?

A project can appear to work and still contain problems:

- A password or API key may have been committed.
- An endpoint may accept unsafe input.
- A function may hide errors instead of handling them.
- A dependency may have a known security issue.
- Important edge cases may not have tests.
- A code change may fix one bug but break another.
- AI-generated code may contain unfinished or incorrect logic.

Checking every file manually takes time. CodeGuard adds another review step to help find these problems earlier.

### What CodeGuard does

1. Looks through the selected project folder.
2. Runs its built-in code and security checks.
3. Uses optional external tools when installed.
4. Runs supported project tests when enabled.
5. Uses an AI model to review selected code and suggest improvements.
6. Can prepare proposed fixes in a temporary working copy.
7. Checks proposed changes and can reject changes that make checks or tests worse.
8. Creates Markdown, HTML and JSON reports.

The exact checks depend on the project language, installed tools, configuration and available tests.

---

## 2. Main benefits

| Benefit | Why it is useful |
|---|---|
| Extra review layer | Gives your code another check before you ship it. |
| Local AI option | Can use Qwen through Ollama without a paid AI API. |
| Lower running cost | Local inference does not charge per request; your computer still uses power and memory. |
| Project-folder workflow | Review an existing project without rewriting it for CodeGuard. |
| Security checks | Looks for selected risky code patterns and exposed secrets. |
| Test execution | Runs supported tests to catch some regressions. |
| Fix review | Checks proposed fixes before offering them for application. |
| Reports | Saves findings in formats that are easy to read or process. |
| Optional CI use | Can be added to a GitHub Actions workflow. |

### Who can use it?

- Students checking college and final-year projects.
- Developers reviewing personal or client projects.
- People using AI coding tools such as Antigravity, Cursor or other code generators.
- Small teams that want an additional automated review step.
- Hackathon participants who want to check a project before submission.

---

## 3. What does it check?

The current version has built-in checks that are strongest for Python, plus a smaller set of general and JavaScript-oriented checks.

| Area | Examples |
|---|---|
| Security | Risky `eval`/`exec`, shell command use, SQL patterns, unsafe YAML or pickle use, weak hashes, disabled TLS verification |
| Secrets | Possible hardcoded API keys, tokens, passwords and private keys |
| Code quality | Mutable defaults, unfinished stubs, TODO markers, swallowed exceptions and high-complexity code |
| JavaScript | Selected risky patterns such as possible unsafe HTML injection |
| Project workflow | Missing README or `.gitignore`, committed `.env`, risky GitHub Actions patterns and Dockerfile hygiene |
| Dependencies | Unpinned Python requirements and known vulnerable packages when `pip-audit` is installed |
| Tests | Runs supported test commands and records pass/fail results |

Optional tools include:

- **Bandit** — additional Python security checks.
- **Ruff** — Python linting.
- **pip-audit** — Python dependency vulnerability checks.

Install the optional tools with:

```bash
python -m pip install -e ".[tools]"
```

CodeGuard only reports what its rules and tools can detect. It does not understand every possible application-specific risk.

---

## 4. AI model: free local Qwen with Ollama

CodeGuard's default AI provider is **Ollama**, with **Qwen2.5-Coder 3B** as the configured default model.

You can also select a smaller model for a low-memory computer.

### Why Qwen and Ollama?

- Ollama runs the model on your own computer.
- Local inference does not require a paid API key.
- After the model is downloaded, local review can work without internet access.
- Your code is not sent to a third-party AI inference provider when you use local Ollama.
- You can choose a smaller or larger model based on your machine.

The first model download requires internet. Hardware, electricity and storage are still required.

### Recommended model for different computers

Approximate model download sizes are shown below. Actual RAM use depends on context length, quantization, operating system and other running applications.

| Model | Approx. download | Practical guidance |
|---|---:|---|
| Qwen2.5-Coder 0.5B | 0.4 GB | Very limited hardware; weaker reasoning |
| Qwen2.5-Coder 1.5B | 1 GB | Good starting point for low-memory computers |
| Qwen2.5-Coder 3B | 1.9 GB | Better starting point when more memory is available |
| Qwen2.5-Coder 7B | 4.7 GB | Prefer a computer with substantially more RAM |
| Qwen2.5-Coder 14B | 9 GB | High-memory computer recommended |

These are approximate model-file sizes, **not** total system RAM requirements.

### Suggested computer requirements

| Resource | Basic local use | More comfortable use |
|---|---|---|
| RAM | 8 GB, with a small model | 16 GB or more |
| Free storage | 5 GB | 15–20 GB |
| GPU | Not required | Helpful, but not compulsory |
| Python | 3.10+ | 3.11+ |
| Internet | Needed for initial downloads | Needed for updates and online tools |

An 8 GB laptop can run a small model, but Windows, the IDE, the project and Ollama all share system memory. Large projects or test suites may make the computer slow. Start with the 1.5B model and close other heavy applications.

### Install Ollama and Qwen

1. Download Ollama: https://ollama.com/download
2. Open PowerShell or Terminal.
3. Download the smaller model:

```bash
ollama pull qwen2.5-coder:1.5b
```

4. Test that it works:

```bash
ollama run qwen2.5-coder:1.5b
```

To use the 1.5B model with CodeGuard in the current PowerShell window:

```powershell
$env:CODEGUARD_MODEL="qwen2.5-coder:1.5b"
```

For the default 3B model instead:

```bash
ollama pull qwen2.5-coder:3b
```

The default provider settings are:

```text
Provider: Ollama
Model: qwen2.5-coder:3b
URL: http://localhost:11434
API key: Not required
```

Keep Ollama running while CodeGuard performs AI review. If Ollama or the selected model is unavailable, CodeGuard can still perform its non-AI checks.

---

## 5. Install CodeGuard

### Requirements

- Python 3.10 or newer.
- Windows, Linux or macOS.
- Ollama only if you want local AI reasoning.
- Git is recommended so you can review and undo changes.

### Download and install

Download and extract the CodeGuard ZIP. Open a terminal in the extracted `codeguard-agent` folder.

Check Python:

```bash
python --version
```

Install CodeGuard in editable mode:

```bash
python -m pip install -e .
```

Check the command:

```bash
codeguard --version
```

If the `codeguard` command is not found, try running it as a Python module from the project directory:

```bash
python -m codeguard --help
```

---

## 6. Review any project folder

You do not need to copy your application source code into the CodeGuard repository.

For example, imagine your project looks like this:

```text
MyProject/
├── backend/
├── frontend/
├── package.json
├── requirements.txt
└── README.md
```

Open a terminal in `MyProject` and run:

```bash
codeguard review .
```

To review another folder, provide its path:

```bash
codeguard review "C:\Projects\MyProject"
```

### Useful commands

Run a normal review:

```bash
codeguard review .
```

Create reports in Markdown, JSON and HTML:

```bash
codeguard review . --format md,json,html
```

Try fixes in a temporary copy and create a patch:

```bash
codeguard review . --fix
```

Apply accepted, verified fixes to the project:

```bash
codeguard review . --apply
```

Run without AI:

```bash
codeguard review . --no-llm
```

Skip tests:

```bash
codeguard review . --no-tests
```

Skip optional external tools:

```bash
codeguard review . --no-external
```

Use Docker for test execution:

```bash
codeguard review . --sandbox docker
```

Set a minimum score for a CI quality gate:

```bash
codeguard review . --fail-under 70
```

### Important difference between `--fix` and `--apply`

- `--fix` tries changes in a temporary copy and creates a patch. It does not directly overwrite your project files.
- `--apply` also writes accepted fixes into your project.

Always commit your work or make a backup before applying changes. Review the patch yourself.

---

## 7. Where are the reports?

By default, reports are saved in:

```text
codeguard-report/
├── report.md
├── report.html
└── report.json
```

The exact generated filenames are printed by the CLI after a scan.

- **Markdown** — easy to read in GitHub or a text editor.
- **HTML** — convenient for viewing a report in a browser.
- **JSON** — useful for scripts and integrations.

The report includes findings, severity counts, scorecard information, test results and fix details where available.

---

## 8. How reliable is CodeGuard?

This is an important question. CodeGuard is an assistant for finding problems, not a guarantee that a project is secure.

It uses several kinds of checks:

| Check type | What it can tell you | Limitation |
|---|---|---|
| Built-in rules | Whether code matches known risky patterns | Cannot detect every vulnerability |
| External scanners | Additional issues covered by those tools | Depends on tool coverage and configuration |
| AI review | Possible logic issues and explanations | AI can be wrong or miss issues |
| Tests | Whether tested behaviour passed | Untested behaviour can still be broken |
| Fix verification | Whether certain checks or tests got worse after a fix | Passing checks does not prove the fix is perfect |

### How does it reduce false alarms?

CodeGuard combines rule-based findings, optional scanner output, AI reasoning and test results. An AI suspicion by itself should not be treated as proof.

For important findings, a developer should inspect:

1. The affected file and line.
2. The explanation and evidence.
3. Whether the issue can be reproduced.
4. The result from relevant tests or security tools.
5. Whether the suggested fix is correct for the application.

### Can it find 100% of bugs or vulnerabilities?

No. No automated tool can honestly promise that.

It may miss complex business-logic bugs, runtime issues, race conditions, access-control mistakes, problems in external services and vulnerabilities that are not covered by its rules or tests.

**Use CodeGuard as an extra reviewer. Do not use its score as a security certification or as the only approval before production deployment.**

---

## 9. Privacy and safe use

### Local AI privacy

When you use Ollama locally, model inference happens on your computer. CodeGuard does not need to upload your source code to a third-party AI provider for that local inference.

If you configure an external OpenAI-compatible or Anthropic provider, the code sent for review goes to that provider and is subject to its terms and data policies.

### Running project tests safely

Tests execute project code. Do not run unknown projects casually on your main machine.

- Prefer Docker sandbox mode for untrusted code.
- Review Docker and sandbox settings before use.
- Do not run untrusted code with administrator privileges.
- Keep secrets out of test environments.
- Do not expose the local HTTP server publicly without production security work.

---

## 10. Optional HTTP dashboard and API

CodeGuard also includes a local HTTP API and upload dashboard.

Start the server:

```bash
python -m codeguard serve
```

By default, it listens at:

```text
http://127.0.0.1:8080
```

Open that address in your browser to try the local dashboard.

The API includes scan and report endpoints, API-key support and plan/billing hooks. This is a development capability, not a claim that a production multi-tenant SaaS deployment is ready. Read `docs/DEPLOYMENT.md` before exposing it beyond localhost.

---

## 11. GitHub Actions

The repository includes an example GitHub workflow and an action definition.

See:

- `examples/github-workflow.yml`
- `action.yml`

These can be used as a starting point for adding CodeGuard checks to a repository workflow. Review and configure the workflow for your own project and CI environment before enabling it on important repositories.

---

## 12. Project structure

```text
codeguard-agent/
├── codeguard/
│   ├── pipeline.py       # Review pipeline
│   ├── llm.py            # Ollama and optional provider adapters
│   ├── scanner.py        # Built-in scanning
│   ├── fixer.py          # Fix proposal and verification
│   ├── testrunner.py     # Test execution
│   ├── report.py         # Report generation
│   ├── scoring.py        # Scorecard
│   ├── server.py         # HTTP API and dashboard
│   └── ...
├── tests/                # Automated tests
├── examples/             # Example project and workflow
├── docs/
│   ├── LOCAL_LLM.md
│   ├── RULES.md
│   ├── ARCHITECTURE.md
│   └── DEPLOYMENT.md
├── action.yml
├── Dockerfile
├── pyproject.toml
└── README.md
```

---

## 13. Current limitations

Please read these before relying on CodeGuard:

- Built-in analysis is currently strongest for Python. JavaScript/TypeScript checks are more limited.
- It is not a replacement for a full enterprise SAST platform or a professional penetration test.
- Smaller local models can give weaker or incorrect reasoning.
- AI review depends on model availability and context limits.
- Test-based verification is only as useful as the project's tests.
- If a project has no tests, verification is weaker; syntax checks and rescanning cannot prove behaviour is correct.
- Running arbitrary project tests is risky without isolation.
- Cloud deployment, production authentication, billing operations and multi-tenant hardening require additional work.

---

## 14. Roadmap

Potential future improvements:

- Better JavaScript, TypeScript, Java, Go and C/C++ analysis.
- Hardware detection and automatic model recommendations.
- More built-in security rules.
- Better evidence and reproducibility for findings.
- Test generation for changed code.
- Improved false-positive handling.
- Richer dashboard and scan history.
- GitHub pull-request review automation.
- Cloud-hosted dashboard and orchestration.
- Team controls and audit history.

Roadmap items are plans, not features promised by the current release.

---

## 15. Contributing

Contributions, bug reports and suggestions are welcome.

Helpful contributions include:

- New detection rules with tests.
- Fixes for false positives and false negatives.
- Better language support.
- Improved model prompts and provider compatibility.
- Test-runner improvements.
- Documentation and installation fixes.

For security rules, include examples that should trigger the rule and examples that should not.

---

## 16. License

See the `LICENSE` file in this repository for license terms.

---

## Final note

**CodeGuard is an extra pair of eyes for your code.**

Use it after generating code, before opening a pull request, or before deploying a project. Let it identify suspicious areas, explain possible risks, run available checks and prepare fixes for your review.

**Review before you deploy. 🛡️**
