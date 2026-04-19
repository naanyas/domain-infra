"""
Free / local email enrichment — no vendor API.

Covers four signals of the paid email-validation vendors' feature set using
only local libraries and one optional HTTP call to Gravatar:

    is_disposable    — bundled open-source blocklist (disposable-email-domains pkg)
    is_role_account  — local heuristic against a curated role-handle list
    mx_reachable     — DNS MX query via dnspython (already in deps)
    has_gravatar     — 1 HTTP HEAD to gravatar.com (free, no auth)

Any individual check failing is swallowed — the email entity keeps its default
value and the verdict pipeline continues.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Iterable

import dns.exception
import dns.resolver
import requests
from disposable_email_domains import blocklist

from apps.entities.models import ContactEmail

logger = logging.getLogger(__name__)

# Role accounts — local curated list. Not exhaustive, but covers 95%+ of
# common role handles. Extend as customer patterns surface.
ROLE_HANDLES: frozenset[str] = frozenset({
    "admin", "administrator", "hostmaster", "postmaster", "webmaster",
    "abuse", "noc", "security", "root",
    "info", "contact", "hello", "help", "support", "feedback",
    "sales", "marketing", "press", "media", "pr",
    "billing", "accounts", "accounting", "finance",
    "hr", "jobs", "careers", "recruiting",
    "no-reply", "noreply", "donotreply", "do-not-reply",
    "mailer-daemon", "nobody", "null",
})

GRAVATAR_URL = "https://www.gravatar.com/avatar/{hash}?d=404&s=1"
GRAVATAR_TIMEOUT_SEC = 3
DNS_TIMEOUT_SEC = 3


# ----------------------------------------------------------------------
# Individual checks
# ----------------------------------------------------------------------


def check_disposable(domain: str) -> bool:
    return (domain or "").lower() in blocklist


def check_role_account(handle: str) -> bool:
    return (handle or "").lower() in ROLE_HANDLES


def check_mx_reachable(domain: str) -> bool | None:
    """Returns True if MX exists, False if clearly no MX, None if DNS error (indeterminate)."""
    if not domain:
        return None
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_TIMEOUT_SEC
        resolver.timeout = DNS_TIMEOUT_SEC
        answers = resolver.resolve(domain, "MX")
        for _ in answers:
            return True
        return False
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return False
    except dns.exception.DNSException:
        return None  # temporary DNS issue — don't assert either way


def check_gravatar(email: str) -> bool | None:
    """
    Gravatar returns 200 if the email has an avatar, 404 (with ?d=404) otherwise.
    Returns None on network error (don't assert).
    """
    if not email or "@" not in email:
        return None
    digest = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    try:
        resp = requests.head(
            GRAVATAR_URL.format(hash=digest),
            timeout=GRAVATAR_TIMEOUT_SEC,
            allow_redirects=False,
        )
    except requests.RequestException:
        return None
    if resp.status_code == 200:
        return True
    if resp.status_code in (404, 410):
        return False
    return None


# ----------------------------------------------------------------------
# Pipeline entry point
# ----------------------------------------------------------------------


def enrich_contact_email(email: ContactEmail) -> None:
    """Populate ContactEmail fields from local free sources. Called on first creation."""
    try:
        updates: list[str] = []

        disposable = check_disposable(email.domain)
        if disposable != email.is_disposable:
            email.is_disposable = disposable
            updates.append("is_disposable")

        role = check_role_account(email.handle)
        if role != email.is_role_account:
            email.is_role_account = role
            updates.append("is_role_account")

        mx = check_mx_reachable(email.domain)
        if mx != email.mx_reachable:
            email.mx_reachable = mx
            updates.append("mx_reachable")

        gravatar = check_gravatar(email.normalized)
        if gravatar != email.has_gravatar:
            email.has_gravatar = gravatar
            updates.append("has_gravatar")

        if updates:
            email.save(update_fields=updates)
    except Exception:
        logger.exception("email enrichment failed for %s", email.normalized)
