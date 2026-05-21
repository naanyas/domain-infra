"""
IPQualityScore Email Validation enricher.

API docs: https://ipqualityscore.com/documentation/email-validation/overview

Returns rich email risk data: fraud_score, deliverability band, spam-trap score,
leaked/breach flag, catch_all/honeypot/recent_abuse/suspect booleans, domain age,
and IPQS's own first_seen timestamp for the email (distinct from OUR first_seen
which tracks when we first observed the email in our customer data).

Separate quota from IPQS Proxy Detection. The free tier is small (~200/month)
so this enricher is only called on FRESH email entities, not on every backfill.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime

import requests
from django.utils import timezone

from apps.entities.models import ContactEmail

logger = logging.getLogger(__name__)

IPQS_EMAIL_BASE = "https://ipqualityscore.com/api/json/email"
IPQS_EMAIL_TIMEOUT_SEC = 8


def _api_key() -> str:
    return os.environ.get("IPQS_API_KEY", "")


def lookup(email: str) -> dict | None:
    key = _api_key()
    if not key or not email or "@" not in email:
        return None
    url = f"{IPQS_EMAIL_BASE}/{key}/{email}"
    try:
        resp = requests.get(url, timeout=IPQS_EMAIL_TIMEOUT_SEC)
    except requests.RequestException:
        logger.exception("IPQS email request failed for %s", email)
        return None
    if resp.status_code != 200:
        logger.warning("IPQS email non-200 for %s: status=%s body=%s", email, resp.status_code, resp.text[:200])
        return None
    data = resp.json()
    if not data.get("success"):
        logger.warning("IPQS email lookup failure for %s: %s", email, data.get("message"))
        return None
    return data


def _parse_iso(value) -> datetime | None:
    """Parse IPQS's ISO-ish date strings (they use 'Z' suffix)."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _parse_first_seen(data: dict) -> datetime | None:
    fs = data.get("first_seen") or {}
    if isinstance(fs, dict):
        return _parse_iso(fs.get("iso"))
    return None


def _parse_domain_age_days(data: dict) -> int | None:
    da = data.get("domain_age") or {}
    if not isinstance(da, dict):
        return None
    dt = _parse_iso(da.get("iso"))
    if dt is None:
        return None
    return max(0, (timezone.now() - dt).days)


def _as_bool_or_none(value) -> bool | None:
    """Only flip true/false from actual booleans — leave None if field absent or non-bool."""
    if isinstance(value, bool):
        return value
    return None


def _as_int_or_none(value) -> int | None:
    if isinstance(value, bool):  # bool is a subclass of int in Python
        return None
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def apply_to_contact_email(email: ContactEmail, data: dict) -> None:
    """Populate IPQS fields on a ContactEmail from the API response."""
    email.ipqs_valid = _as_bool_or_none(data.get("valid"))
    email.ipqs_dns_valid = _as_bool_or_none(data.get("dns_valid"))
    email.ipqs_fraud_score = _as_int_or_none(data.get("fraud_score"))
    email.ipqs_smtp_score = _as_int_or_none(data.get("smtp_score"))
    email.ipqs_overall_score = _as_int_or_none(data.get("overall_score"))
    email.ipqs_deliverability = str(data.get("deliverability") or "")[:20]
    email.ipqs_catch_all = _as_bool_or_none(data.get("catch_all"))
    email.ipqs_honeypot = _as_bool_or_none(data.get("honeypot"))
    email.ipqs_suspect = _as_bool_or_none(data.get("suspect"))
    email.ipqs_recent_abuse = _as_bool_or_none(data.get("recent_abuse"))
    email.ipqs_leaked = _as_bool_or_none(data.get("leaked"))
    email.ipqs_frequent_complainer = _as_bool_or_none(data.get("frequent_complainer"))
    email.ipqs_spam_trap_score = str(data.get("spam_trap_score") or "")[:20]
    email.ipqs_suggested_domain = str(data.get("suggested_domain") or "")[:253]
    email.ipqs_first_seen = _parse_first_seen(data)
    email.ipqs_domain_age_days = _parse_domain_age_days(data)
    email.ipqs_enriched_at = timezone.now()

    # Cross-populate our native fields when IPQS confirms.
    if data.get("disposable") is True:
        email.is_disposable = True
    if data.get("leaked") is True and email.breach_count == 0:
        # IPQS only gives a bool; if you want the real count, add the Leaked Data API.
        email.breach_count = 1

    email.save(update_fields=[
        "ipqs_valid", "ipqs_dns_valid", "ipqs_fraud_score", "ipqs_smtp_score",
        "ipqs_overall_score", "ipqs_deliverability", "ipqs_catch_all", "ipqs_honeypot",
        "ipqs_suspect", "ipqs_recent_abuse", "ipqs_leaked", "ipqs_frequent_complainer",
        "ipqs_spam_trap_score", "ipqs_suggested_domain", "ipqs_first_seen",
        "ipqs_domain_age_days", "ipqs_enriched_at", "is_disposable", "breach_count",
    ])


def enrich_contact_email(email: ContactEmail) -> None:
    """One-shot: call IPQS + apply + save. Swallows all errors (pipeline shouldn't fail)."""
    try:
        data = lookup(email.normalized)
        if data:
            apply_to_contact_email(email, data)
    except Exception:
        logger.exception("IPQS email enrichment failed for %s", email.normalized)
