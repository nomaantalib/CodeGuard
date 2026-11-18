"""HTTP API + tiny dashboard (stdlib only). Run: python -m codeguard serve

POST /api/scan            body = .zip, Authorization: Bearer <key>   -> 202 {id}
GET  /api/scans/<id>      status + summary
GET  /api/scans/<id>/report.(html|md|json|patch)
GET  /api/usage
POST /admin/keys          X-Admin-Token, {"email","plan"}
POST /webhooks/stripe     Stripe-Signature verified
"""
from __future__ import annotations

import hmac
import io
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from .billing import PLANS, apply_event, quota_exceeded, verify_stripe_signature
from .config import load_config
from .pipeline import review
from .report import write_reports
from .store import Store


class Settings:
    def __init__(self):
        e = os.environ.get
        self.data_dir = Path(e("CODEGUARD_DATA", "./codeguard-data")).resolve()
        self.admin_token = e("CODEGUARD_ADMIN_TOKEN", "")
        self.stripe_secret = e("STRIPE_WEBHOOK_SECRET", "")
        self.sandbox = e("CODEGUARD_SANDBOX", "docker")  # docker | none
        self.allow_unsafe_local = e("CODEGUARD_ALLOW_UNSAFE_LOCAL") == "1"
        self.docker_image = e("CODEGUARD_DOCKER_IMAGE", "python:3.12-slim")
        self.workers = int(e("CODEGUARD_WORKERS", "2"))


def safe_extract(data: bytes, dest: Path, max_files: int = 5000, max_bytes: int = 200 * 1024 * 1024) -> Path:
    """Extract an untrusted zip: no path traversal, no symlinks, bounded size and file count."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    base = dest.resolve()
    total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        infos = z.infolist()
        if len(infos) > max_files:
            raise ValueError("archive has too many files")
        for i in infos:
            target = (base / i.filename).resolve()
            if target != base and base not in target.parents:
                raise ValueError("unsafe path in archive")
            if (i.external_attr >> 16) & 0o170000 == 0o120000:
                continue  # skip symlinks
            if i.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(i) as src, open(target, "wb") as out:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError("archive too large when extracted")
                    out.write(chunk)
    entries = [p for p in base.iterdir() if p.name != "__MACOSX"]
    return entries[0] if len(entries) == 1 and entries[0].is_dir() else base


def run_job(store: Store, settings: Settings, scan_id: str, account: dict, data: bytes, want_fix: bool, want_llm: bool):
    plan = PLANS[account["plan"]]
    tmp = Path(tempfile.mkdtemp(prefix="cg-job-"))
    try:
        store.update_scan(scan_id, status="running")
        root = safe_extract(data, tmp / "src")
        docker_ok = shutil.which("docker") is not None
        run_tests = (settings.sandbox == "docker" and docker_ok) or settings.allow_unsafe_local
        # Server-side overrides always win over a customer-supplied codeguard.toml.
        cfg = load_config(root, {
            "sandbox": "docker" if (settings.sandbox == "docker" and docker_ok) else "none",
            "run_tests": run_tests, "use_llm": bool(want_llm and plan["llm"]),
            "docker_network": "none", "docker_image": settings.docker_image, "test_timeout": 300})
        r = review(root, cfg, fix=bool(want_fix and plan["fix"]), apply=False)
        if not run_tests:
            r.notes.append("Tests were not executed: no sandbox available on this server (customer code is never run unsandboxed).")
        if want_fix and not plan["fix"]:
            r.notes.append("Auto-fix requires the Pro plan.")
        out = settings.data_dir / "scans" / scan_id
        write_reports(r, out)
        summary = {"before": r.score_before, "after": r.score_after, "fixes": len(r.fixes),
                   "accepted_fixes": sum(f.status == "accepted" for f in r.fixes), "notes": r.notes}
        store.update_scan(scan_id, status="done", finished=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                          score=r.score_after["overall"], summary=json.dumps(summary))
    except Exception as e:  # never leak internals to the customer
        print(f"[codeguard] job {scan_id} failed: {e!r}", file=sys.stderr)
        store.update_scan(scan_id, status="error", error=str(e)[:300])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


DASHBOARD = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>CodeGuard</title><style>body{font:16px system-ui;max-width:640px;margin:30px auto;padding:0 14px}
input,button{font:inherit;margin:4px 0;padding:6px}pre{background:#8881;padding:10px;overflow:auto}</style>
<h1>CodeGuard</h1><p>Upload a <b>.zip</b> of your project to review it.</p>
<input id=key type=password placeholder="API key" size=40><br><input id=file type=file accept=".zip"><br>
<label><input id=fix type=checkbox> auto-fix (Pro)</label> <label><input id=llm type=checkbox> AI review (Pro)</label><br>
<button id=go>Scan</button><pre id=out></pre>
<script>
const $=id=>document.getElementById(id),H=()=>({Authorization:'Bearer '+$('key').value.trim()});
$('go').onclick=async()=>{const f=$('file').files[0];if(!f){$('out').textContent='Choose a zip first';return}
$('out').textContent='Uploading...';
const r=await fetch(`/api/scan?fix=${+$('fix').checked}&llm=${+$('llm').checked}`,{method:'POST',headers:H(),body:f});
const j=await r.json();if(!r.ok){$('out').textContent=j.error||r.status;return}poll(j.id)};
async function poll(id){const r=await fetch('/api/scans/'+id,{headers:H()});const j=await r.json();
$('out').textContent=JSON.stringify(j,null,2);
if(j.status==='queued'||j.status==='running')return setTimeout(()=>poll(id),1500);
if(j.status==='done'){const b=document.createElement('button');b.textContent='Open report';
b.onclick=async()=>{const h=await fetch(`/api/scans/${id}/report.html`,{headers:H()});window.open(URL.createObjectURL(await h.blob()))};
document.body.appendChild(b)}}
</script>"""
CTYPES = {"html": "text/html; charset=utf-8", "md": "text/markdown; charset=utf-8",
          "json": "application/json", "patch": "text/plain; charset=utf-8"}


def make_handler(store: Store, settings: Settings, pool: ThreadPoolExecutor):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"CodeGuard/{__version__}"

        def log_message(self, fmt, *args):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

        def _send(self, code, body, ctype="application/json", extra=None):
            if isinstance(body, (dict, list)):
                body = json.dumps(body)
            body = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _err(self, code, msg):
            self._send(code, {"error": msg})

        def _account(self):
            h = self.headers.get("Authorization", "")
            return store.authenticate(h[7:].strip()) if h.startswith("Bearer ") else None

        def _body(self, limit):
            n = int(self.headers.get("Content-Length") or 0)
            if n > limit:
                return None
            return self.rfile.read(n)

        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/":
                return self._send(200, DASHBOARD, "text/html; charset=utf-8")
            if u.path == "/healthz":
                return self._send(200, {"ok": True, "version": __version__})
            acct = self._account()
            if not acct:
                return self._err(401, "missing or invalid API key")
            if u.path == "/api/usage":
                plan = PLANS[acct["plan"]]
                return self._send(200, {"plan": acct["plan"], "used_this_month": store.scans_this_month(acct["id"]),
                                        "limit": plan["scans_per_month"], "features": {"fix": plan["fix"], "llm": plan["llm"]}})
            m = re.fullmatch(r"/api/scans/([0-9a-f]{16})(?:/report\.(html|md|json|patch))?", u.path)
            if not m:
                return self._err(404, "not found")
            scan = store.get_scan(m.group(1))
            if not scan or scan["account_id"] != acct["id"]:
                return self._err(404, "not found")
            if not m.group(2):
                scan["summary"] = json.loads(scan["summary"]) if scan.get("summary") else None
                scan.pop("account_id", None)
                return self._send(200, scan)
            name = "codeguard-fixes.patch" if m.group(2) == "patch" else f"codeguard-report.{m.group(2)}"
            f = settings.data_dir / "scans" / scan["id"] / name
            if not f.is_file():
                return self._err(404, "report not available")
            extra = {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"}
            return self._send(200, f.read_bytes(), CTYPES[m.group(2)], extra)

        def do_POST(self):
            u = urlparse(self.path)
            if u.path == "/webhooks/stripe":
                raw = self._body(1_000_000)
                if raw is None or not verify_stripe_signature(raw, self.headers.get("Stripe-Signature", ""), settings.stripe_secret):
                    return self._err(400, "invalid signature")
                try:
                    msg = apply_event(store, json.loads(raw))
                except ValueError:
                    return self._err(400, "bad payload")
                return self._send(200, {"received": True, "result": msg})
            if u.path == "/admin/keys":
                tok = self.headers.get("X-Admin-Token", "")
                if not settings.admin_token or not hmac.compare_digest(tok, settings.admin_token):
                    return self._err(403, "forbidden")
                try:
                    data = json.loads(self._body(10_000) or b"{}")
                    email, plan = str(data["email"]), data.get("plan", "free")
                except (ValueError, KeyError):
                    return self._err(400, 'expected JSON {"email": "...", "plan": "free|pro|enterprise"}')
                if plan not in PLANS:
                    return self._err(400, "unknown plan")
                return self._send(201, {"api_key": store.create_key(email, plan), "plan": plan})
            if u.path == "/api/scan":
                acct = self._account()
                if not acct:
                    return self._err(401, "missing or invalid API key")
                plan = PLANS[acct["plan"]]
                if quota_exceeded(acct["plan"], store.scans_this_month(acct["id"])):
                    return self._err(429, "monthly scan quota reached - upgrade your plan")
                data = self._body(plan["max_upload_mb"] * 1024 * 1024)
                if data is None:
                    return self._err(413, f"upload exceeds {plan['max_upload_mb']} MB for your plan")
                if not zipfile.is_zipfile(io.BytesIO(data)):
                    return self._err(400, "body must be a .zip archive")
                q = parse_qs(u.query)
                scan_id = secrets.token_hex(8)
                store.create_scan(acct["id"], scan_id)
                pool.submit(run_job, store, settings, scan_id, acct, data,
                            q.get("fix", ["0"])[0] == "1", q.get("llm", ["0"])[0] == "1")
                return self._send(202, {"id": scan_id, "status": "queued"})
            return self._err(404, "not found")

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8080):
    settings = Settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    store = Store(settings.data_dir / "codeguard.db")
    pool = ThreadPoolExecutor(max_workers=settings.workers)
    httpd = ThreadingHTTPServer((host, port), make_handler(store, settings, pool))
    print(f"CodeGuard {__version__} listening on http://{host}:{port}  (data: {settings.data_dir})", file=sys.stderr)
    if not settings.admin_token:
        print("warning: CODEGUARD_ADMIN_TOKEN not set - /admin/keys is disabled (use `codeguard keys`)", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        pool.shutdown(wait=False)
