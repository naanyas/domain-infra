"""
Entity-level reputation bumping. Counterpart to fingerprint reputation — but at
the more granular per-entity level (each IP, NS, MX, registrar, contact email,
name, phone, submitter IP gets its own flagged/approved counters).

Phase 1 schema only had `net_flagged_count` and `net_approved_count` on each
entity — review decisions don't bump either counter (entity reputation is
binary-ish, unlike fingerprint reputation which carries more nuance).
"""
from __future__ import annotations

import logging

from django.db.models import F

from apps.entities.models import (
    ContactEmail,
    ContactName,
    ContactPhone,
    IPAddress,
    MXHost,
    Nameserver,
    Registrar,
    SubmitterIP,
)
from apps.submissions.models import Submission, Verdict

logger = logging.getLogger(__name__)


def bump_entity_reputation(submission: Submission, verdict_decision: str) -> dict:
    """
    Increment `net_flagged_count` or `net_approved_count` on every entity
    linked to this submission. Returns a counts-per-entity-type dict for logging.
    """
    if verdict_decision == Verdict.DECISION_DENY:
        field = "net_flagged_count"
    elif verdict_decision == Verdict.DECISION_APPROVE:
        field = "net_approved_count"
    else:
        return {}  # review + failed submissions don't move entity reputation

    counts: dict[str, int] = {}
    increment = {field: F(field) + 1}

    # ----- Domain-side entities (only present if a DomainScan exists) -----
    try:
        ds = getattr(submission, "domain_scan", None)
    except Submission.domain_scan.RelatedObjectDoesNotExist:  # type: ignore[attr-defined]
        ds = None

    if ds is not None:
        ip_pks = list(IPAddress.objects.filter(scan_links__domain_scan=ds).distinct().values_list("pk", flat=True))
        if ip_pks:
            counts["ip_addresses"] = IPAddress.objects.filter(pk__in=ip_pks).update(**increment)

        ns_pks = list(Nameserver.objects.filter(scan_links__domain_scan=ds).distinct().values_list("pk", flat=True))
        if ns_pks:
            counts["nameservers"] = Nameserver.objects.filter(pk__in=ns_pks).update(**increment)

        mx_pks = list(MXHost.objects.filter(scan_links__domain_scan=ds).distinct().values_list("pk", flat=True))
        if mx_pks:
            counts["mx_hosts"] = MXHost.objects.filter(pk__in=mx_pks).update(**increment)

        if ds.registrar_id:
            counts["registrar"] = Registrar.objects.filter(pk=ds.registrar_id).update(**increment)

    # ----- Contact-side entities -----
    if submission.contact_email_id:
        counts["contact_emails"] = ContactEmail.objects.filter(pk=submission.contact_email_id).update(**increment)
    if submission.contact_name_id:
        counts["contact_names"] = ContactName.objects.filter(pk=submission.contact_name_id).update(**increment)
    if submission.contact_phone_id:
        counts["contact_phones"] = ContactPhone.objects.filter(pk=submission.contact_phone_id).update(**increment)
    if submission.submitter_ip_id:
        counts["submitter_ips"] = SubmitterIP.objects.filter(pk=submission.submitter_ip_id).update(**increment)

    logger.info("entity reputation bump for submission %s: %s", submission.id, counts)
    return counts
