"""Plans, quotas and Stripe webhook handling (stdlib only)."""
from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any, Dict, Optional

PLANS: Dict[str, Dict[str, Any]] = {
    "free": {"scans_per_month": 5, "fix": False, "llm": False, "max_upload_mb": 10},
    "pro": {"scans_per_month": 200, "fix": True, "llm": True, "max_upload_mb": 50},
    "enterprise": {"scans_per_month": None, "fix": True, "llm": True, "max_upload_mb": 200},  # None = unlimited
}


def quota_exceeded(plan: str, used: int) -> bool:
    limit = PLANS.get(plan, PLANS["free"])["scans_per_month"]
    return limit is not None and used >= limit


def verify_stripe_signature(payload: bytes, header: str, secret: str, tolerance: int = 300,
                            now: Optional[float] = None) -> bool:
    """Implements Stripe's documented scheme: HMAC-SHA256 over '<timestamp>.<payload>'."""
    if not header or not secret:
        return False
    parts = dict(p.split("=", 1) for p in header.split(",") if "=" in p)  # v1 may repeat; take all below
    sigs = [p.split("=", 1)[1] for p in header.split(",") if p.startswith("v1=")]
    ts = parts.get("t")
    if not ts or not sigs or not ts.isdigit():
        return False
    if abs((now if now is not None else time.time()) - int(ts)) > tolerance:
        return False
    expected = hmac.new(secret.encode(), ts.encode() + b"." + payload, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, s) for s in sigs)


def apply_event(store, event: Dict[str, Any]) -> str:
    """Translate a Stripe event into a plan change. Returns a short description."""
    t = event.get("type", "")
    obj = (event.get("data") or {}).get("object") or {}
    if t == "checkout.session.completed":
        email = (obj.get("customer_details") or {}).get("email") or obj.get("customer_email")
        plan = (obj.get("metadata") or {}).get("plan", "pro")
        if email and plan in PLANS:
            store.upsert_account(email, plan, obj.get("customer"))
            return f"{email} -> {plan}"
    elif t == "customer.subscription.deleted":
        store.set_plan_by_customer(obj.get("customer"), "free")
        return "subscription cancelled -> free"
    elif t == "customer.subscription.updated" and obj.get("status") in ("past_due", "unpaid", "canceled"):
        store.set_plan_by_customer(obj.get("customer"), "free")
        return f"subscription {obj.get('status')} -> free"
    return "ignored"
