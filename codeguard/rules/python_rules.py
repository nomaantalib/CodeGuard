"""Python rules: AST-based checks tuned for issues common in AI-generated code."""
from __future__ import annotations

import ast
import importlib.util
import re
import sys
from typing import List, Optional, Set

from ..models import Finding
from .catalog import mk

STDLIB = set(getattr(sys, "stdlib_module_names", ())) | {"__future__"}
PICKLE_CALLS = {"pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads", "marshal.load",
                "marshal.loads", "dill.load", "dill.loads", "shelve.open"}
ALIASES = {  # distribution name -> import name (normalized)
    "pyyaml": "yaml", "pillow": "pil", "beautifulsoup4": "bs4", "scikit_learn": "sklearn",
    "opencv_python": "cv2", "opencv_python_headless": "cv2", "python_dateutil": "dateutil",
    "pyjwt": "jwt", "python_dotenv": "dotenv", "attrs": "attr", "protobuf": "google",
    "pycryptodome": "crypto", "psycopg2_binary": "psycopg2", "mysqlclient": "mysqldb",
    "python_multipart": "multipart", "pyserial": "serial", "ruamel_yaml": "ruamel",
}
SQL_WORDS = re.compile(r"\b(select|insert|update|delete|drop|create|alter|where)\b", re.I)


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name.lower())


class Context:
    """Project-level facts the per-file rules need."""

    def __init__(self, declared: Optional[Set[str]] = None, local: Optional[Set[str]] = None, max_complexity: int = 12):
        self.declared = {norm(d) for d in (declared or set())}
        self.local = set(local or set())
        self.max_complexity = max_complexity
        self._cache = {}

    def resolvable(self, top: str) -> bool:
        if top in self._cache:
            return self._cache[top]
        t = norm(top)
        ok = (top in STDLIB or top in self.local or t in self.declared
              or any(ALIASES.get(d) == t for d in self.declared)
              or any(d.startswith(t + "_") for d in self.declared))
        if not ok:
            try:
                ok = importlib.util.find_spec(top) is not None
            except (ImportError, ValueError, AttributeError):
                ok = False
        self._cache[top] = ok
        return ok


def dotted(n) -> str:
    parts = []
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        parts.append(n.id)
        return ".".join(reversed(parts))
    return ""


def _kw(call: ast.Call, name: str):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _is(node, value) -> bool:
    return isinstance(node, ast.Constant) and node.value is value


def _sqlish(node) -> bool:
    text = " ".join(n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str))
    return bool(SQL_WORDS.search(text))


def _dynamic(node) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return not (isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def _complexity(fn) -> int:
    c = 1
    for n in ast.walk(fn):
        if isinstance(n, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp, ast.ExceptHandler, ast.Assert)):
            c += 1
        elif isinstance(n, ast.BoolOp):
            c += len(n.values) - 1
        elif isinstance(n, ast.comprehension):
            c += 1 + len(n.ifs)
    return c


def _guarded_nodes(tree) -> Set[int]:
    """ids of nodes inside try/except ImportError or `if TYPE_CHECKING:` (optional imports)."""
    ids: Set[int] = set()
    for t in ast.walk(tree):
        guard = False
        body = []
        if isinstance(t, ast.Try):
            for h in t.handlers:
                if h.type is None:
                    guard = True
                    continue
                elts = h.type.elts if isinstance(h.type, ast.Tuple) else [h.type]
                if any(dotted(e) in ("ImportError", "ModuleNotFoundError", "Exception") for e in elts):
                    guard = True
            body = t.body
        elif isinstance(t, ast.If) and dotted(t.test).endswith("TYPE_CHECKING"):
            guard, body = True, t.body
        if guard:
            for stmt in body:
                for n in ast.walk(stmt):
                    ids.add(id(n))
    return ids


def _is_stub(fn) -> bool:
    body = [s for s in fn.body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                                       and isinstance(s.value.value, str))]
    if len(body) != 1 or fn.name.startswith("__"):
        return False
    for d in fn.decorator_list:
        name = dotted(d.func if isinstance(d, ast.Call) else d).lower()
        if "abstract" in name or "overload" in name:
            return False
    s = body[0]
    if isinstance(s, ast.Pass):
        return True
    if isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and s.value.value is Ellipsis:
        return True
    if isinstance(s, ast.Raise) and s.exc is not None:
        exc = s.exc.func if isinstance(s.exc, ast.Call) else s.exc
        return dotted(exc) == "NotImplementedError"
    return False


def scan_python(rel: str, src: str, ctx: Context) -> List[Finding]:
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return [mk("PY016", rel, e.lineno or 1, f"Syntax error: {e.msg}", "The file does not parse; fix before anything else.")]
    except (ValueError, RecursionError):
        return []
    out: List[Finding] = []
    guarded = _guarded_nodes(tree)
    seen_imports: Set[str] = set()

    def check_import(top: str, node):
        if top in seen_imports or id(node) in guarded:
            return
        seen_imports.add(top)
        if not ctx.resolvable(top):
            out.append(mk("PY015", rel, node.lineno,
                          f"Import '{top}' is not stdlib, local, declared or installed - verify the package really exists",
                          "AI tools sometimes invent package names; typosquatted names are a supply-chain risk."))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            end = getattr(node, "end_lineno", node.lineno)
            if name == "eval":
                out.append(mk("PY001", rel, node.lineno, "eval() executes arbitrary code", "Use ast.literal_eval() or explicit parsing.", end, True))
            elif name == "exec":
                out.append(mk("PY002", rel, node.lineno, "exec() executes arbitrary code", "Remove dynamic execution.", end))
            elif name in ("os.system", "os.popen"):
                out.append(mk("PY003", rel, node.lineno, f"{name}() runs a shell command", "Use subprocess.run([...], shell=False) with an argument list.", end))
            elif name.startswith("subprocess.") and _is(_kw(node, "shell"), True):
                const = bool(node.args) and isinstance(node.args[0], ast.Constant)
                out.append(mk("PY003", rel, node.lineno, f"{name}(shell=True) enables shell injection",
                              "Pass an argument list and drop shell=True.", end, severity="medium" if const else "high"))
            elif name == "yaml.load" and _kw(node, "Loader") is None and len(node.args) < 2:
                out.append(mk("PY004", rel, node.lineno, "yaml.load() without a safe Loader can run arbitrary code", "Use yaml.safe_load().", end, True))
            elif name in PICKLE_CALLS:
                out.append(mk("PY005", rel, node.lineno, f"{name}() can execute code when loading untrusted data", "Use JSON or another data-only format.", end))
            elif name in ("hashlib.md5", "hashlib.sha1") and _kw(node, "usedforsecurity") is None:
                out.append(mk("PY006", rel, node.lineno, f"{name}() is a weak hash", "Use hashlib.sha256 (or argon2/bcrypt for passwords).", end, True))
            elif name == "tempfile.mktemp":
                out.append(mk("PY011", rel, node.lineno, "tempfile.mktemp() is race-prone", "Use tempfile.mkstemp() or NamedTemporaryFile.", end))
            elif name == "os.chmod" and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and node.args[1].value == 0o777:
                out.append(mk("PY013", rel, node.lineno, "chmod 777 makes the file world-writable", "Use the least permissive mode (e.g. 0o600/0o644).", end))
            elif name == "ssl._create_unverified_context":
                out.append(mk("PY007", rel, node.lineno, "Unverified SSL context disables certificate checks", "Use ssl.create_default_context().", end))
            if _is(_kw(node, "verify"), False):
                out.append(mk("PY007", rel, node.lineno, "verify=False disables TLS certificate validation", "Remove verify=False.", end, True))
            if _is(_kw(node, "debug"), True) and (name == "run" or name.endswith(".run")):
                out.append(mk("PY012", rel, node.lineno, "Server started with debug=True", "Disable debug outside local development.", end, True))
            if (isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "executemany", "executescript", "raw")
                    and node.args and _dynamic(node.args[0]) and _sqlish(node.args[0])):
                out.append(mk("PY010", rel, node.lineno, "SQL built with string formatting/concatenation",
                              "Use parameterized queries: cursor.execute(sql, params).", end))
        elif isinstance(node, ast.Assign):
            if _is(node.value, True) and any(isinstance(t, ast.Name) and t.id.lower() == "debug" for t in node.targets):
                out.append(mk("PY012", rel, node.lineno, "DEBUG is set to True", "Load from environment; default to False.", node.end_lineno, True))
        elif isinstance(node, ast.ExceptHandler):
            if node.type is None:
                out.append(mk("PY008", rel, node.lineno, "Bare 'except:' also catches KeyboardInterrupt/SystemExit", "Catch Exception (or something narrower).", node.lineno, True))
            broad = node.type is None or dotted(node.type) in ("Exception", "BaseException")
            if broad and all(isinstance(s, ast.Pass) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)) for s in node.body):
                out.append(mk("PY009", rel, node.lineno, "Exception is silently swallowed", "Log or handle the error."))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defaults = list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]
            for d in defaults:
                if isinstance(d, (ast.List, ast.Dict, ast.Set)) or (isinstance(d, ast.Call) and dotted(d.func) in ("list", "dict", "set")):
                    out.append(mk("PY014", rel, node.lineno, f"Mutable default argument in {node.name}()", "Default to None and create the object inside the function."))
                    break
            cx = _complexity(node)
            if cx > ctx.max_complexity:
                out.append(mk("PY018", rel, node.lineno, f"{node.name}() has cyclomatic complexity {cx}", "Split into smaller functions."))
            if _is_stub(node):
                out.append(mk("PY017", rel, node.lineno, f"{node.name}() is an unfinished stub", "Implement it or remove it."))
        elif isinstance(node, ast.Import):
            for a in node.names:
                check_import(a.name.split(".")[0], node)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                check_import(node.module.split(".")[0], node)
    return out
