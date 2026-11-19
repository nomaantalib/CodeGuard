import unittest
from pathlib import Path

from codeguard.config import Config, load_config
from codeguard.llm_client import LLMClient, PRESETS
from codeguard.planner import plan_repo, compute_file_risk
from codeguard.multipass import GroundedFinding, verify_grounding, make_numbered_chunks
from codeguard.scoring import score, composite_score
from codeguard.testaudit import audit_test_suite
from benchmarks.runner import run_benchmark


class CodeGuardV2Tests(unittest.TestCase):
    def test_presets_exist(self):
        for name in ("ollama", "deepseek", "qwen", "glm", "kimi", "openrouter", "anthropic"):
            self.assertIn(name, PRESETS)
            self.assertTrue(bool(PRESETS[name]["base_url"]))

    def test_numbered_chunks(self):
        lines = "\n".join(f"def func_{i}(): pass" for i in range(150))
        chunks = make_numbered_chunks(lines, window_size=50, overlap=10)
        self.assertGreaterEqual(len(chunks), 3)
        self.assertIn("1 | def func_0", chunks[0][2])

    def test_grounding_gate_drops_hallucinations(self):
        code = "def authenticate(user, password):\n    if user == 'admin' and password == 'secret':\n        return True\n"
        # Grounded finding: quote exists in code
        gf_valid = GroundedFinding("auth.py", 2, 2, "security", "high", 0.9, "hardcoded credential", "user == 'admin'", "bypass")
        self.assertTrue(verify_grounding(gf_valid, code))

        # Ungrounded finding: quote does NOT exist in code
        gf_fake = GroundedFinding("auth.py", 2, 2, "security", "high", 0.9, "fake claim", "eval(user_input)", "exploit")
        self.assertFalse(verify_grounding(gf_fake, code))

    def test_file_risk_computation(self):
        risky_code = "import os\ndef run(cmd):\n    os.system(cmd)\n    password = '123'\n"
        clean_code = "def add(a, b):\n    return a + b\n"
        risk_high = compute_file_risk("run.py", risky_code)
        risk_low = compute_file_risk("clean.py", clean_code)
        self.assertGreater(risk_high.risk_score, risk_low.risk_score)

    def test_composite_scoring_llm_and_deterministic(self):
        from codeguard.rules.catalog import mk
        det_findings = [mk("PY001", "a.py", 1, "eval", "fix it", severity="high")]
        llm_findings = [mk("LLM001", "b.py", 5, "logic flaw", "fix it", severity="medium", source="llm_v2")]
        all_findings = det_findings + llm_findings

        # 1. With LLM
        res_full = composite_score(all_findings, None, llm_used=True)
        self.assertEqual(res_full["status"], "FINAL")
        self.assertFalse(res_full["is_partial"])
        self.assertIn(res_full["band"], ("Good", "Needs Work", "CRITICAL"))

        # 2. Without LLM (Honest reporting: never invent LLM score)
        res_partial = composite_score(all_findings, None, llm_used=False)
        self.assertEqual(res_partial["status"], "PARTIAL (Deterministic Only)")
        self.assertTrue(res_partial["is_partial"])
        self.assertIsNone(res_partial["llm_score"])

    def test_test_audit_assertion_counter(self):
        audit = audit_test_suite([Path(__file__)])
        self.assertGreater(audit.assert_count, 5)
        self.assertEqual(len(audit.superficial_tests), 0)

    def test_calibration_benchmark_passes(self):
        p, r, f1 = run_benchmark()
        self.assertGreaterEqual(f1, 0.80)


if __name__ == "__main__":
    unittest.main()
