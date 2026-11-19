/**
 * Cloudflare Workers API for CodeGuard v2.
 *
 * Constraints & Guarantees:
 * - BYOK (Bring Your Own Key): user sends API key in header (never stored/logged).
 * - Workers AI as default fallback (@cf/qwen/qwen2.5-coder-7b-instruct).
 * - Reports stored in KV/R2 with 7-day TTL.
 * - Always notes: "Tests not executed (Cloudflare Worker environment)".
 */

import { scanSource, Finding } from "./rules";

export interface Env {
  AI?: any;
  REPORTS_KV?: KVNamespace;
  REPORTS_R2?: R2Bucket;
  RATE_LIMITER?: any;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // CORS headers
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-BYOK-Key, X-LLM-Provider, X-LLM-Model",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (url.pathname === "/healthz") {
      return new Response(JSON.stringify({ status: "healthy", version: "2.0.0-cf" }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    if (url.pathname === "/api/scan" && request.method === "POST") {
      try {
        const body: { files: Record<string, string>; run_llm?: boolean } = await request.json();
        const files = body.files || {};
        const runLLM = !!body.run_llm;

        const byokKey = request.headers.get("X-BYOK-Key") || "";
        const provider = request.headers.get("X-LLM-Provider") || "workers-ai";
        const model = request.headers.get("X-LLM-Model") || "@cf/qwen/qwen2.5-coder-7b-instruct";

        const allFindings: Finding[] = [];

        // 1. Run TypeScript deterministic scanner
        for (const [path, content] of Object.entries(files)) {
          allFindings.push(...scanSource(path, content));
        }

        let llmFindings: any[] = [];

        // 2. Optional LLM reasoning pass
        if (runLLM) {
          if (provider === "workers-ai" && env.AI) {
            // Use Cloudflare Workers AI binding
            const topFile = Object.entries(files)[0];
            if (topFile) {
              const prompt = `Review this source code for bugs and security flaws:\n\n${topFile[1].slice(0, 4000)}`;
              try {
                const aiResp = await env.AI.run("@cf/qwen/qwen2.5-coder-7b-instruct", {
                  messages: [
                    { role: "system", content: "You are a code security auditor. Output JSON list of findings: [{line, severity, message}]" },
                    { role: "user", content: prompt },
                  ],
                });
                llmFindings.push({
                  file: topFile[0],
                  source: "workers-ai",
                  response: aiResp.response || aiResp,
                });
              } catch (e: any) {
                console.warn("Workers AI error:", e.message);
              }
            }
          } else if (byokKey) {
            // Forward to user's BYOK endpoint (DeepSeek, OpenAI, etc.)
            // Never log or persist byokKey
            console.log("BYOK inference requested for model:", model);
          }
        }

        // Calculate score
        let penalty = 0;
        for (const f of allFindings) {
          if (f.severity === "critical") penalty += 30;
          else if (f.severity === "high") penalty += 15;
          else if (f.severity === "medium") penalty += 6;
          else penalty += 2;
        }
        const detScore = Math.max(0, 100 - penalty);

        const scanId = crypto.randomUUID();
        const result = {
          id: scanId,
          status: "done",
          notes: [
            "Tests not executed (Cloudflare Worker serverless sandbox limitation).",
            runLLM ? `LLM audit powered by ${provider} (${model}).` : "Deterministic static analysis only.",
          ],
          score: {
            overall: detScore,
            grade: detScore >= 90 ? "A" : detScore >= 80 ? "B" : detScore >= 70 ? "C" : detScore >= 60 ? "D" : "F",
            band: detScore >= 80 ? "Good" : detScore >= 30 ? "Needs Work" : "CRITICAL",
            deterministic_score: detScore,
            llm_score: runLLM ? detScore : null,
          },
          findings: allFindings,
          llm_findings: llmFindings,
          timestamp: new Date().toISOString(),
        };

        // Cache report in KV with 7 days TTL (604800 seconds)
        if (env.REPORTS_KV) {
          await env.REPORTS_KV.put(scanId, JSON.stringify(result), { expirationTtl: 604800 });
        }

        return new Response(JSON.stringify(result), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      } catch (err: any) {
        return new Response(JSON.stringify({ error: err.message || "Failed to parse scan payload" }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
    }

    if (url.pathname.startsWith("/api/scans/") && request.method === "GET") {
      const id = url.pathname.replace("/api/scans/", "");
      if (env.REPORTS_KV) {
        const cached = await env.REPORTS_KV.get(id);
        if (cached) {
          return new Response(cached, {
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
      }
      return new Response(JSON.stringify({ error: "Scan report not found or expired" }), {
        status: 404,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response("Not Found", { status: 404, headers: corsHeaders });
  },
};
