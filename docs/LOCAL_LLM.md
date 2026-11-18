# Local LLM setup

CodeGuard's default reasoning provider is Ollama running locally. It does not send
source code to a third-party inference API and does not need a paid API key.

## 1. Install a local model runtime

Install Ollama from https://ollama.com, then run:

```bash
ollama pull qwen2.5-coder:3b
ollama serve
```

Keep Ollama running. The first pull downloads model weights; later scans use the
local copy. For a machine with more RAM/VRAM, you can select another model:

```bash
ollama pull qwen2.5-coder:7b
CODEGUARD_MODEL=qwen2.5-coder:7b codeguard review .
```

## 2. Run CodeGuard in any project/task folder

Install CodeGuard once:

```bash
python -m pip install -e /path/to/codeguard-agent
```

From the project to review:

```bash
codeguard review .
codeguard review . --fix
```

`--fix` creates a patch after verification. It does not modify project files.
Use `--apply` only when you want verified changes written into the project.

## 3. Provider settings

- `CODEGUARD_LLM_PROVIDER=ollama` (default)
- `CODEGUARD_MODEL=qwen2.5-coder:3b` (default)
- `CODEGUARD_LLM_URL=http://localhost:11434` (default)

OpenAI-compatible endpoints are optional and may be free-tier or paid depending
on the provider. Configure `CODEGUARD_LLM_PROVIDER=openai-compatible`,
`CODEGUARD_LLM_URL`, `CODEGUARD_MODEL`, and `CODEGUARD_LLM_API_KEY`.
An Anthropic adapter remains optional for users who explicitly choose it.

## Important

"Free" means the local model weights and inference are free to run; hardware,
electricity and initial model download still have costs. A small model is less
capable than larger models, so CodeGuard combines model reasoning with static
analysis and test execution. An LLM suspicion alone is not proof of a flaw.
