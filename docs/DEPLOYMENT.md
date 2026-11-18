# Deployment, GitHub hosting and billing

## 1. Put it on GitHub (private repo!)
```bash
cd codeguard-agent
git init -b main && git add . && git commit -m "CodeGuard Agent v0.1"
gh repo create YOUR_ORG/codeguard-agent --private --source=. --push      # or create it in the web UI and push
git tag v1 && git push --tags
```
* Keep the repo **private**: the code is your product. Public repos are free to copy.
* `LICENSE` is a placeholder - choose a commercial EULA, or a source-available license (BSL) if you want visibility.
* GitHub Actions CI (`.github/workflows/ci.yml`) runs the tests on Python 3.10-3.13 and scans the repo with itself.
* Customers can use the Action from a private repo only if you grant access (Settings -> Actions -> Access) or you publish a small public wrapper repo containing just `action.yml` that installs from your private package registry. Simplest path to revenue: sell the **hosted API** and ship only a tiny public Action that calls it (v0.2).

## 2. Run the server in production
Customer code = untrusted code. Requirements:
1. A **VM** (not a container) with Docker installed; run the API as a systemd service on that host so `docker run` works.
2. `export CODEGUARD_SANDBOX=docker` (default) and pre-pull `python:3.12-slim` (and `node:20-slim`). Test runs use `--network none`,
   so dependencies must already be in the image: build your own image with common packages and set `CODEGUARD_DOCKER_IMAGE`.
3. TLS via a reverse proxy (Caddy / nginx). Never expose the Python server directly.
4. Set `CODEGUARD_ADMIN_TOKEN` (long random), `STRIPE_WEBHOOK_SECRET`, `CODEGUARD_LLM_PROVIDER`, `CODEGUARD_MODEL`, `CODEGUARD_LLM_URL`, `CODEGUARD_DATA=/var/lib/codeguard` and back that folder up (SQLite + reports).
5. For stronger isolation than plain Docker use gVisor/Firecracker, and per-job ephemeral VMs for enterprise customers.

```ini
# /etc/systemd/system/codeguard.service
[Service]
EnvironmentFile=/etc/codeguard.env
ExecStart=/usr/bin/python3 -m codeguard serve --host 127.0.0.1 --port 8080
Restart=always
User=codeguard
```
The included `Dockerfile` is **scan-only** (no sandbox available inside it, so tests are skipped and the report says so).

## 3. API reference
| Method & path | Auth | Purpose |
|---|---|---|
| `POST /api/scan?fix=0\|1&llm=0\|1` (body: .zip) | `Authorization: Bearer <key>` | queue a scan -> `202 {id}`; 429 when monthly quota reached; 413 if upload too big |
| `GET /api/scans/<id>` | Bearer | status (`queued/running/done/error`) + score summary |
| `GET /api/scans/<id>/report.html\|md\|json\|patch` | Bearer | artifacts (served with a strict CSP) |
| `GET /api/usage` | Bearer | plan, usage this month, limits |
| `POST /admin/keys` `{"email","plan"}` | `X-Admin-Token` | create an API key (shown once) |
| `POST /webhooks/stripe` | Stripe signature | plan upgrades/downgrades |
| `GET /healthz`, `GET /` | none | health, dashboard |

Plans live in `billing.PLANS` (free: 5 scans/mo, scan-only; pro: 200/mo + auto-fix + AI; enterprise: unlimited). Edit freely.

## 4. Stripe (monthly subscriptions)
1. In Stripe create Products/Prices: *Pro* (monthly recurring) and *Enterprise*.
2. Create a Payment Link or Checkout Session per plan with metadata `plan=pro` (or `enterprise`).
   **Verify in test mode** that the metadata arrives on `checkout.session.completed` (it is how the webhook knows the plan).
3. Add a webhook endpoint `https://YOUR_HOST/webhooks/stripe` for: `checkout.session.completed`,
   `customer.subscription.updated`, `customer.subscription.deleted`. Put the signing secret in `STRIPE_WEBHOOK_SECRET`.
4. Flow: customer pays -> account upgraded to the plan -> you (v0.1) issue a key with `codeguard keys --email X --plan pro`
   (or `POST /admin/keys`). Cancelled / past-due subscriptions fall back to `free` automatically.
5. Test with the Stripe CLI: `stripe listen --forward-to localhost:8080/webhooks/stripe`.

## 5. Pre-launch checklist
- [ ] Sandbox verified: run a scan of a project whose test tries network + file access; confirm it is contained
- [ ] Privacy policy + terms: what code you store (reports only; uploads are deleted after the job), retention, subprocessors (configured LLM provider, Stripe)
- [ ] Rotate `CODEGUARD_ADMIN_TOKEN`; keys are hashed so a DB leak does not leak keys
- [ ] Rate limiting / WAF at the reverse proxy; backups of `CODEGUARD_DATA`
- [ ] Monitor LLM spend per scan (`max_llm_files` caps it)

## 6. Local LLM setup (recommended for the local edition)

Install Ollama and download a free local model:
```bash
ollama pull qwen2.5-coder:3b
ollama serve
```
CodeGuard uses `http://localhost:11434` by default. No API key or paid inference
service is needed. The model weights are downloaded once and inference runs locally.
