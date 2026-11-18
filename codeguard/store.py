"""SQLite persistence: accounts, hashed API keys, scan jobs."""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL,
  plan TEXT NOT NULL DEFAULT 'free', stripe_customer TEXT, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS api_keys(hash TEXT PRIMARY KEY, account_id INTEGER NOT NULL,
  created TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, account_id INTEGER NOT NULL, status TEXT NOT NULL,
  created TEXT NOT NULL, finished TEXT, score INTEGER, summary TEXT, error TEXT);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._run(lambda c: c.executescript(SCHEMA))

    def _run(self, fn):
        with closing(sqlite3.connect(self.path, timeout=15)) as c:
            c.row_factory = sqlite3.Row
            with c:
                return fn(c)

    def upsert_account(self, email: str, plan: str = "free", stripe_customer: Optional[str] = None) -> int:
        email = email.strip().lower()

        def go(c):
            row = c.execute("SELECT id FROM accounts WHERE email=?", (email,)).fetchone()
            if row:
                c.execute("UPDATE accounts SET plan=?, stripe_customer=COALESCE(?, stripe_customer) WHERE id=?",
                          (plan, stripe_customer, row["id"]))
                return row["id"]
            return c.execute("INSERT INTO accounts(email,plan,stripe_customer,created) VALUES(?,?,?,?)",
                             (email, plan, stripe_customer, _now())).lastrowid
        return self._run(go)

    def create_key(self, email: str, plan: Optional[str] = None) -> str:
        email = email.strip().lower()
        row = self._run(lambda c: c.execute("SELECT id, plan FROM accounts WHERE email=?", (email,)).fetchone())
        acct = self.upsert_account(email, plan or (row["plan"] if row else "free"))
        raw = "cg_" + secrets.token_urlsafe(24)
        self._run(lambda c: c.execute("INSERT INTO api_keys(hash,account_id,created) VALUES(?,?,?)", (_hash(raw), acct, _now())))
        return raw

    def authenticate(self, raw: str) -> Optional[Dict[str, Any]]:
        if not raw:
            return None
        row = self._run(lambda c: c.execute(
            "SELECT a.id, a.email, a.plan FROM api_keys k JOIN accounts a ON a.id=k.account_id WHERE k.hash=? AND k.revoked=0",
            (_hash(raw),)).fetchone())
        return dict(row) if row else None

    def set_plan_by_customer(self, customer: Optional[str], plan: str) -> None:
        if customer:
            self._run(lambda c: c.execute("UPDATE accounts SET plan=? WHERE stripe_customer=?", (plan, customer)))

    def scans_this_month(self, account_id: int) -> int:
        start = datetime.now(timezone.utc).strftime("%Y-%m-01")
        return self._run(lambda c: c.execute("SELECT COUNT(*) n FROM scans WHERE account_id=? AND created>=?",
                                             (account_id, start)).fetchone()["n"])

    def create_scan(self, account_id: int, scan_id: str) -> None:
        self._run(lambda c: c.execute("INSERT INTO scans(id,account_id,status,created) VALUES(?,?,?,?)",
                                      (scan_id, account_id, "queued", _now())))

    def update_scan(self, scan_id: str, **fields) -> None:
        keys = ("status", "finished", "score", "summary", "error")
        vals = [fields.get(k) for k in keys]  # static SQL: None keeps the existing value
        self._run(lambda c: c.execute(
            "UPDATE scans SET status=COALESCE(?,status), finished=COALESCE(?,finished), score=COALESCE(?,score), "
            "summary=COALESCE(?,summary), error=COALESCE(?,error) WHERE id=?", (*vals, scan_id)))

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        row = self._run(lambda c: c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone())
        return dict(row) if row else None
