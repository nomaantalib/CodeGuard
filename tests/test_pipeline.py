import shutil
import tempfile
import unittest
from pathlib import Path

from codeguard.config import load_config
from codeguard.pipeline import review
from codeguard.scoring import score
from codeguard.models import Finding, RunResult
from codeguard.testrunner import parse_output, regressed

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_app"


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.proj = self.tmp / "app"
        shutil.copytree(EXAMPLE, self.proj)
        self.cfg = load_config(self.proj, {"use_llm": False, "use_external_tools": False})

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_review_only_does_not_touch_files(self):
        before = (self.proj / "app.py").read_text()
        r = review(self.proj, self.cfg)
        self.assertEqual((self.proj / "app.py").read_text(), before)
        self.assertTrue(r.tests_before.ran and r.tests_before.failed == 0)
        self.assertGreater(len(r.findings_before), 5)

    def test_fix_improves_score_and_reverts_breaking_fix(self):
        r = review(self.proj, self.cfg, fix=True)
        self.assertGreater(r.score_after["overall"], r.score_before["overall"])
        status = {(f.rules[0], f.status) for f in r.fixes}
        self.assertIn(("PY004", "accepted"), status)
        self.assertIn(("PY001", "reverted"), status)  # eval -> literal_eval breaks calc("2+3"): must be rolled back
        self.assertIn("safe_load", r.patch)
        self.assertNotIn("literal_eval", r.patch)
        self.assertEqual(r.tests_after.failed, 0)

    def test_apply_writes_verified_fixes(self):
        review(self.proj, self.cfg, fix=True, apply=True)
        text = (self.proj / "app.py").read_text()
        self.assertIn("yaml.safe_load", text)
        self.assertIn("eval(expr)", text)  # the reverted fix is not applied
        again = review(self.proj, self.cfg)
        self.assertEqual(again.tests_before.failed, 0)

    def test_gate(self):
        cfg = load_config(self.proj, {"use_llm": False, "use_external_tools": False, "fail_on": "high"})
        self.assertFalse(review(self.proj, cfg).gate["passed"])


class HelperTests(unittest.TestCase):
    def test_parse_unittest_and_pytest(self):
        self.assertEqual(parse_output("Ran 5 tests in 0.1s\n\nOK\n", 0), ("unittest", 5, 0, 0))
        self.assertEqual(parse_output("Ran 5 tests in 0.1s\n\nFAILED (failures=1, errors=1)\n", 1), ("unittest", 3, 1, 1))
        self.assertEqual(parse_output("1 failed, 3 passed in 0.2s\n", 1), ("pytest", 3, 1, 0))

    def test_regressed(self):
        base = RunResult(ran=True, passed=3)
        self.assertTrue(regressed(RunResult(ran=True, passed=2, failed=1), base))
        self.assertFalse(regressed(RunResult(ran=True, passed=3), base))

    def test_score_bounds(self):
        fs = [Finding("X", "critical", "security", "a", 1, "m") for _ in range(10)]
        s = score(fs, RunResult(ran=True, passed=1, failed=1))
        self.assertEqual(s["categories"]["security"], 0)
        self.assertEqual(s["categories"]["tests"], 50)
        self.assertEqual(score([], None)["overall"], 100)


if __name__ == "__main__":
    unittest.main()
