/**
 * TypeScript port of CodeGuard deterministic security and quality rules.
 * Runs inside Cloudflare Workers without requiring subprocesses or Python runtime.
 */

export interface Finding {
  rule: string;
  file: string;
  line: number;
  message: string;
  severity: "critical" | "high" | "medium" | "low";
  category: "security" | "quality" | "deps";
}

const SECRET_PATTERNS = [
  { name: "AWS access key id", regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/, sev: "critical" },
  { name: "Private key block", regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/, sev: "critical" },
  { name: "GitHub token", regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/, sev: "critical" },
  { name: "Slack token", regex: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/, sev: "high" },
  { name: "Stripe live key", regex: /\b[sr]k_live_[0-9a-zA-Z]{16,}\b/, sev: "critical" },
  { name: "Google API key", regex: /\bAIza[0-9A-Za-z_\-]{35}\b/, sev: "high" },
  { name: "LLM API key", regex: /\bsk-(?:ant-)?[A-Za-z0-9_\-]{32,}\b/, sev: "critical" },
] as const;

export function scanSource(file: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");

  lines.forEach((lineText, idx) => {
    const lineNum = idx + 1;

    // 1. Secrets Check
    for (const pat of SECRET_PATTERNS) {
      if (pat.regex.test(lineText) && !lineText.toLowerCase().includes("example")) {
        findings.push({
          rule: "SEC001",
          file,
          line: lineNum,
          message: `${pat.name} detected`,
          severity: pat.sev as any,
          category: "security",
        });
      }
    }

    // 2. Python-specific regex rules
    if (file.endsWith(".py")) {
      if (/\beval\s*\(/.test(lineText) && !lineText.includes("literal_eval")) {
        findings.push({
          rule: "PY001",
          file,
          line: lineNum,
          message: "Unsafe dynamic evaluation allows arbitrary code execution",
          severity: "high",
          category: "security",
        });
      }
      if (/\bexec\s*\(/.test(lineText)) {
        findings.push({
          rule: "PY002",
          file,
          line: lineNum,
          message: "exec() on dynamic input allows arbitrary code execution",
          severity: "high",
          category: "security",
        });
      }
      if (/yaml\.load\s*\([^,)]*\)/.test(lineText) && !lineText.includes("SafeLoader")) {
        findings.push({
          rule: "PY004",
          file,
          line: lineNum,
          message: "Unsafe yaml.load() without SafeLoader",
          severity: "high",
          category: "security",
        });
      }
      if (/def\s+\w+\([^)]*=\s*(\[\]|\{\})/.test(lineText)) {
        findings.push({
          rule: "PY014",
          file,
          line: lineNum,
          message: "Mutable default argument in function definition",
          severity: "medium",
          category: "quality",
        });
      }
      if (/except\s*:|except\s+Exception\s*:\s*pass/.test(lineText)) {
        findings.push({
          rule: "PY009",
          file,
          line: lineNum,
          message: "Swallowed exception hides runtime failures",
          severity: "low",
          category: "quality",
        });
      }
    }

    // 3. JS / TS checks
    if (file.endsWith(".js") || file.endsWith(".ts")) {
      if (/innerHTML\s*=/.test(lineText)) {
        findings.push({
          rule: "JS001",
          file,
          line: lineNum,
          message: "Direct innerHTML assignment introduces XSS vulnerability",
          severity: "high",
          category: "security",
        });
      }
    }
  });

  return findings;
}
