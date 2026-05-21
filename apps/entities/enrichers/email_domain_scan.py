"""
Run the SDAT domain analyzer against the EMAIL'S domain (not the submission's
domain). Captures infrastructure risk on the email's provider — useful when the
email is on a custom domain (not freemail) because that's an attackable surface.

Skips:
 * freemail providers (gmail, yahoo, ...) — scanning these is pure noise
 * when email domain matches the submitted domain (the pipeline already scanned it)

Adds ~15-25s to the pipeline on the FIRST submission of an email on a
scannable domain. Cached on ContactEmail — subsequent submissions of the
same email skip this entirely.
"""
from __future__ import annotations

import logging
from dataclasses import asdict

from django.utils import timezone

from apps.entities.freemail import is_freemail
from apps.entities.models import ContactEmail

logger = logging.getLogger(__name__)


def run_email_domain_scan(email: ContactEmail, skip_domain: str = "") -> None:
    """
    Run analyze_domain() against email.domain if it's scannable.
    Stores raw_result + timestamp, or a 'skipped' reason.
    """
    if email.email_domain_scan_at is not None:
        return  # already scanned
    if not email.domain:
        email.email_domain_scan_skipped_reason = "no_domain"
        email.email_domain_scan_at = timezone.now()
        email.save(update_fields=["email_domain_scan_skipped_reason", "email_domain_scan_at"])
        return
    if is_freemail(email.domain):
        email.email_domain_scan_skipped_reason = "freemail"
        email.email_domain_scan_at = timezone.now()
        email.save(update_fields=["email_domain_scan_skipped_reason", "email_domain_scan_at"])
        return
    if skip_domain and email.domain.lower() == skip_domain.lower():
        email.email_domain_scan_skipped_reason = "same_as_submitted_domain"
        email.email_domain_scan_at = timezone.now()
        email.save(update_fields=["email_domain_scan_skipped_reason", "email_domain_scan_at"])
        return

    try:
        from analyzer import analyze_domain
        result = analyze_domain(email.domain)
        raw = asdict(result) if hasattr(result, "__dataclass_fields__") else dict(result)
        email.email_domain_scan_raw = raw
        email.email_domain_scan_at = timezone.now()
        email.email_domain_scan_skipped_reason = ""
        email.save(update_fields=["email_domain_scan_raw", "email_domain_scan_at", "email_domain_scan_skipped_reason"])
    except Exception:
        logger.exception("SDAT email-domain scan failed for %s", email.domain)
