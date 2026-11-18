import hashlib
import hmac
import io
import json
import shutil
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from pathlib import Path

from codeguard.billing import apply_event, quota_exceeded, verify_stripe_signature
from codeguard.server import Settings, make_handler, safe_extract
from codeguard.store import Store

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_app"


def make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


class ZipSafetyTests(unittest.TestCase):
    def test_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(ValueError):
            safe_extract(make_zip({"../evil.py": "x"}), Path(d) / "out")

    def test_rejects_zip_bomb_by_size(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(ValueError):
            safe_extract(make_zip({"a.txt": "x" * 5000}), Path(d) / "out", max_bytes=1000)

    def test_unwraps_single_top_folder(self):
        with tempfile.TemporaryDirectory() as d:
            root = safe_extract(make_zip({"proj/a.py": "x=1"}), Path(d) / "out")
            self.assertEqual(root.name, "proj")


class BillingTests(unittest.TestCase):
    def test_stripe_signature(self):
        payload, secret, ts = b'{"a":1}', "whsec_test", 1_700_000_000
        sig = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
        header = f"t={ts},v1={sig}"
        self.assertTrue(verify_stripe_signature(payload, header, secret, now=ts + 10))
        self.assertFalse(verify_stripe_signature(payload + b"x", header, secret, now=ts + 10))
        self.assertFalse(verify_stripe_signature(payload, header, secret, now=ts + 10_000))  # replay window
        self.assertFalse(verify_stripe_signature(payload, header, "", now=ts))

    def test_quota(self):
        self.assertTrue(quota_exceeded("free", 5))
        self.assertFalse(quota_exceeded("pro", 5))
        self.assertFalse(quota_exceeded("enterprise", 10 ** 6))

    def test_plan_changes_via_events(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d) / "db.sqlite")
            apply_event(store, {"type": "checkout.session.completed", "data": {"object": {
                "customer_details": {"email": "A@x.com"}, "customer": "cus_1", "metadata": {"plan": "pro"}}}})
            key = store.create_key("a@x.com")
            self.assertEqual(store.authenticate(key)["plan"], "pro")
            apply_event(store, {"type": "customer.subscription.deleted", "data": {"object": {"customer": "cus_1"}}})
            self.assertEqual(store.authenticate(key)["plan"], "free")
            self.assertIsNone(store.authenticate("cg_wrong"))


class ServerE2E(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        s = Settings()
        s.data_dir, s.sandbox, s.allow_unsafe_local, s.admin_token = self.tmp, "none", True, "adm"
        self.store = Store(self.tmp / "db.sqlite")
        self.pool = ThreadPoolExecutor(1)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.store, s, self.pool))
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.pool.shutdown(wait=True)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def call(self, path, data=None, key=None, method=None, headers=None):
        h = dict(headers or {})
        if key:
            h["Authorization"] = f"Bearer {key}"
        req = urllib.request.Request(self.base + path, data=data, headers=h, method=method)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def zip_example(self):
        return make_zip({str(p.relative_to(EXAMPLE)): p.read_text() for p in EXAMPLE.rglob("*.py")} | {"requirements.txt": "pyyaml\nrequests\n"})

    def test_auth_required(self):
        self.assertEqual(self.call("/api/usage")[0], 401)
        self.assertEqual(self.call("/api/scan", b"x", method="POST")[0], 401)

    def test_admin_key_and_full_scan_flow(self):
        code, body = self.call("/admin/keys", json.dumps({"email": "a@x.com", "plan": "pro"}).encode(),
                               method="POST", headers={"X-Admin-Token": "adm"})
        self.assertEqual(code, 201)
        key = json.loads(body)["api_key"]
        self.assertEqual(self.call("/admin/keys", b"{}", method="POST", headers={"X-Admin-Token": "nope"})[0], 403)
        self.assertEqual(self.call("/api/scan", b"not a zip", key=key, method="POST")[0], 400)
        code, body = self.call("/api/scan?fix=1", self.zip_example(), key=key, method="POST")
        self.assertEqual(code, 202)
        sid = json.loads(body)["id"]
        for _ in range(100):
            info = json.loads(self.call(f"/api/scans/{sid}", key=key)[1])
            if info["status"] not in ("queued", "running"):
                break
            time.sleep(0.3)
        self.assertEqual(info["status"], "done", info)
        self.assertGreater(info["summary"]["after"]["overall"], info["summary"]["before"]["overall"])
        self.assertEqual(self.call(f"/api/scans/{sid}/report.html", key=key)[0], 200)
        self.assertEqual(self.call(f"/api/scans/{sid}/report.patch", key=key)[0], 200)
        # another customer cannot read it
        other = self.store.create_key("b@x.com", "free")
        self.assertEqual(self.call(f"/api/scans/{sid}", key=other)[0], 404)
        self.assertEqual(json.loads(self.call("/api/usage", key=key)[1])["used_this_month"], 1)

    def test_free_plan_cannot_autofix(self):
        key = self.store.create_key("c@x.com", "free")
        sid = json.loads(self.call("/api/scan?fix=1", self.zip_example(), key=key, method="POST")[1])["id"]
        for _ in range(100):
            info = json.loads(self.call(f"/api/scans/{sid}", key=key)[1])
            if info["status"] not in ("queued", "running"):
                break
            time.sleep(0.3)
        self.assertEqual(info["summary"]["fixes"], 0)
        self.assertTrue(any("Pro plan" in n for n in info["summary"]["notes"]))


if __name__ == "__main__":
    unittest.main()
