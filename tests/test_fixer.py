import ast
import unittest

from codeguard import fixer
from codeguard.config import Config
from codeguard.rules import python_rules
from codeguard.scanner import scan_source

SRC = '''"""doc"""
from __future__ import annotations
import hashlib
import yaml
import requests

TOKEN = "abcdefgh12345678"


def f(t, u):
    h = hashlib.md5(t.encode()).hexdigest()
    d = yaml.load(t)
    try:
        requests.get(u,
                     verify=False)
    except:
        pass
    return eval(t), h, d
'''


class FixerTests(unittest.TestCase):
    def apply_all(self, src):
        ctx = python_rules.Context({"pyyaml", "requests"}, set())
        for rule in fixer.fixable_rules(scan_source("a.py", src, ctx, Config())):
            findings = scan_source("a.py", src, ctx, Config())
            src = fixer.apply_rule(src, findings, rule)
        return src, ctx

    def test_fixes_apply_and_still_parse(self):
        out, ctx = self.apply_all(SRC)
        ast.parse(out)
        self.assertIn("hashlib.sha256(", out)
        self.assertIn("yaml.safe_load(", out)
        self.assertIn("verify=True", out)
        self.assertIn("except Exception:", out)
        self.assertIn("ast.literal_eval(", out)
        self.assertIn('TOKEN = os.environ.get("TOKEN", "")', out)
        remaining = {f.rule for f in scan_source("a.py", out, ctx, Config())}
        self.assertFalse(remaining & {"PY001", "PY004", "PY006", "PY007", "PY008", "SEC001"})

    def test_imports_go_after_future_and_docstring(self):
        out, _ = self.apply_all(SRC)
        lines = out.splitlines()
        self.assertEqual(lines[0], '"""doc"""')
        self.assertEqual(lines[1], "from __future__ import annotations")
        self.assertIn("import ast", lines[2:6])

    def test_ensure_import_is_idempotent(self):
        once = fixer.ensure_import("import os\nx = 1\n", "os")
        self.assertEqual(once, "import os\nx = 1\n")


if __name__ == "__main__":
    unittest.main()
