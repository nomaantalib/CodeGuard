# Turning it into a monthly business

## Positioning
"AI wrote it. CodeGuard verifies it." Teams adopting AI coding assistants ship faster but need an automated reviewer that
**proves** fixes with their own tests instead of just commenting. Your differentiators vs generic linters/SAST:
hallucinated-package detection, verify-or-revert auto-fix, one scorecard across security + tests + workflow + dependencies,
and a quality gate that drops into CI in one step.

## Suggested pricing (editable in `billing.PLANS`)
| Plan | Price idea | Includes |
|---|---|---|
| Free | $0 | 5 scans/month, static scan + scorecard, no auto-fix - the funnel |
| Pro | per seat or per repo, monthly | 200 scans, auto-fix patches, AI review/fix, PR comments |
| Enterprise | custom annual/monthly | unlimited, SSO, self-hosted runner, audit log, compliance mapping (OWASP/SOC 2 evidence), SLA |

Price against the engineering hours saved per week, not against linters. Validate with 3-5 paid pilots before building more.

## Unit economics to watch
* LLM cost per scan = files reviewed x tokens (cap with `max_llm_files`, `max_file_kb`). Track it per account.
* Compute: sandboxed test runs dominate for large repos - enforce `test_timeout` and upload caps per plan.
* Gross margin target: keep the free tier scan-only (no LLM) so it costs almost nothing.

## Trust is the product
Companies will hand you source code. Ship early: a clear data-retention policy, "we never train on your code", deletion on request,
human-approval before anything merges (the tool produces patches/PRs, never auto-merges), SOC 2 roadmap, and a self-hosted option.

## Roadmap
1. **v0.2** auto-email API key after Stripe checkout; GitHub App (webhooks -> comment + fix PR without a workflow file); public Action that calls the hosted API.
2. **v0.3** more languages (TS/Go/Java) via Semgrep rules; SARIF output for GitHub code scanning; org dashboard + history trends.
3. **v0.4** Postgres + queue workers + per-job ephemeral sandboxes; team accounts, SSO.
4. **v1.0** policy packs (OWASP ASVS, PCI, HIPAA), audit exports, usage-based billing.

## Legal / housekeeping
Choose your license (`LICENSE` is a placeholder), form a company, get terms of service + DPA templates reviewed by a lawyer,
and check third-party licenses before bundling bandit/ruff/semgrep (they are only invoked if the customer has them installed in v0.1).
