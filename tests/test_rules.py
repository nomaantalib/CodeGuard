import textwrap
import unittest

from codeguard.config import Config
from codeguard.rules import generic, python_rules
from codeguard.scanner import scan_source


def rules_for(src, rel="x.py", declared=()):
    ctx = python_rules.Context(set(declared), {"localmod"})
    return {f.rule for f in scan_source(rel, textwrap.dedent(src), ctx, Config())}


class PythonRuleTests(unittest.TestCase):
    def test_dangerous_calls(self):
        got = rules_for("""
            import os, subprocess, pickle, hashlib, yaml, requests, tempfile
            eval("1")
            exec("x=1")
            os.system("ls")
            subprocess.run("ls", shell=True)
            pickle.loads(b"")
            hashlib.md5(b"")
            yaml.load("a: 1")
            requests.get("http://x", verify=False)
            tempfile.mktemp()
        """, declared=["pyyaml", "requests"])
        self.assertTrue({"PY001", "PY002", "PY003", "PY004", "PY005", "PY006", "PY007", "PY011"} <= got)

    def test_sql_injection_detected_but_parameterized_ok(self):
        bad = rules_for('def f(c, n):\n    c.execute(f"SELECT * FROM t WHERE n = {n}")\n')
        ok = rules_for('def f(c, n):\n    c.execute("SELECT * FROM t WHERE n = ?", (n,))\n')
        self.assertIn("PY010", bad)
        self.assertNotIn("PY010", ok)

    def test_quality_rules(self):
        got = rules_for("""
            def a(x=[]):
                try:
                    return x
                except:
                    pass
            def b():
                raise NotImplementedError
        """)
        self.assertTrue({"PY008", "PY009", "PY014", "PY017"} <= got)

    def test_hallucinated_import(self):
        got = rules_for("import totally_fake_pkg_zz\nimport localmod\nimport json\n")
        self.assertIn("PY015", got)
        found = [f for f in scan_source("x.py", "import totally_fake_pkg_zz\nimport localmod\nimport json\n",
                                        python_rules.Context(set(), {"localmod"}), Config()) if f.rule == "PY015"]
        self.assertEqual(len(found), 1)  # local + stdlib are fine

    def test_optional_import_is_not_flagged(self):
        src = "try:\n    import maybe_missing_pkg\nexcept ImportError:\n    maybe_missing_pkg = None\n"
        self.assertNotIn("PY015", rules_for(src))

    def test_declared_alias(self):
        self.assertNotIn("PY015", rules_for("import yaml\n", declared=["PyYAML"]))

    def test_syntax_error(self):
        self.assertIn("PY016", rules_for("def broken(:\n"))

    def test_complexity(self):
        body = "def f(x):\n" + "".join(f"    if x == {i}:\n        return {i}\n" for i in range(15))
        self.assertIn("PY018", rules_for(body))


class SecretTests(unittest.TestCase):
    def test_provider_key_detected_and_masked(self):
        key = "sk_live_" + "aB3dE6gH9jK2mN5pQ8sT"  # built at runtime so this repo has no key-like literal
        out = generic.scan_secrets("a.py", f'KEY = "{key}"\n')
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "critical")
        self.assertNotIn(key, out[0].message)

    def test_placeholders_and_env_are_ignored(self):
        self.assertEqual(generic.scan_secrets("a.py", 'PASSWORD = "changeme-please"\n'), [])
        self.assertEqual(generic.scan_secrets("a.py", 'TOKEN = os.environ["TOKEN"]\n'), [])

    def test_generic_password(self):
        self.assertEqual(len(generic.scan_secrets("a.py", 'db_password = "hunter2hunter2"\n')), 1)


class SuppressionTests(unittest.TestCase):
    def test_inline_ignore(self):
        src = 'import os\nos.system("ls")  # codeguard:ignore=PY003\nos.system("pwd")\n'
        found = [f for f in scan_source("x.py", src, python_rules.Context(), Config()) if f.rule == "PY003"]
        self.assertEqual([f.line for f in found], [3])

    def test_secrets_in_tests_are_low(self):
        out = generic.scan_secrets("tests/test_a.py", 'db_password = "hunter2hunter2"\n')
        self.assertEqual((out[0].severity, out[0].fixable), ("low", False))


class JsRuleTests(unittest.TestCase):
    def test_js(self):
        src = "el.innerHTML = x;\nconst r = eval(s);\n// eval(ignored)\nre.exec(a + b);\n"
        got = {f.rule for f in generic.scan_js("a.js", src)}
        self.assertEqual(got, {"JS001", "JS002"})


if __name__ == "__main__":
    unittest.main()
