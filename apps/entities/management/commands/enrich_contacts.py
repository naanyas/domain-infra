"""
Materialize + enrich contact-side entities (email, name, phone, submitter IP)
for submissions that were bulk-imported without running the full pipeline.

This is the FAST part of the pipeline — ~2-3s per new unique entity, dominated
by IPQS + Gravatar network calls. For comparison, the full pipeline (includes
SDAT analyzer DNS/WHOIS/HTTP) is ~20-30s per row with a domain.

    python manage.py enrich_contacts                   # first 200 submissions missing contact entities
    python manage.py enrich_contacts --limit 1000      # bigger batch
    python manage.py enrich_contacts --limit 0         # ALL (warning: 1000s × 2-3s each)
    python manage.py enrich_contacts --no-gravatar     # skip Gravatar check (saves ~500ms per email)
"""
from __future__ import annotations

import os
import time

from django.core.management.base import BaseCommand, CommandError
from django.db.models import Q

from apps.organizations.models import Organization
from apps.submissions.models import Submission


class Command(BaseCommand):
    help = "Materialize and enrich contact-side entities (email/phone/IP) on submissions missing them."

    def add_arguments(self, parser):
        parser.add_argument("--org", default="acme")
        parser.add_argument("--limit", type=int, default=200,
                            help="Max submissions to process (default 200, 0 = unlimited)")
        parser.add_argument("--no-gravatar", action="store_true",
                            help="Skip Gravatar check to speed up email enrichment.")

    def handle(self, *args, org: str, limit: int, no_gravatar: bool, **options):
        try:
            organization = Organization.objects.get(slug=org)
        except Organization.DoesNotExist as exc:
            raise CommandError(f"No organization with slug '{org}'") from exc

        if no_gravatar:
            # Nuke the check by setting its timeout to 0 via a stub — simpler: patch the function
            import apps.entities.enrichers.email_local as el
            el.check_gravatar = lambda email: None  # type: ignore[assignment]
            self.stdout.write(self.style.NOTICE("Gravatar check disabled for this run."))

        # Submissions that have raw contact data but no linked contact entities.
        qs = Submission.objects.filter(organization=organization).filter(
            Q(contact_email_raw__gt="") |
            Q(contact_name_raw__gt="") |
            Q(contact_phone_raw__gt="") |
            Q(submitter_ip_raw__isnull=False)
        ).filter(
            Q(contact_email__isnull=True) |
            Q(contact_name__isnull=True) |
            Q(contact_phone__isnull=True) |
            Q(submitter_ip__isnull=True)
        ).order_by("created_at")

        if limit > 0:
            qs = qs[:limit]

        total = qs.count()
        if total == 0:
            self.stdout.write("Nothing to enrich — every eligible submission already has linked contact entities.")
            return

        self.stdout.write(f"Enriching contacts on {total} submission(s)...\n")

        from apps.api.services import _materialize_contact_entities

        start = time.time()
        for i, sub in enumerate(qs.iterator(chunk_size=50), start=1):
            t0 = time.time()
            try:
                _materialize_contact_entities(sub)
                dt = time.time() - t0
                ident = sub.contact_email_raw or sub.submitter_ip_raw or sub.contact_phone_raw or sub.contact_name_raw or "—"
                self.stdout.write(f"[{i:>4}/{total}] {ident:45} ({dt:.1f}s)")
            except Exception as exc:
                self.stdout.write(self.style.ERROR(f"[{i:>4}/{total}] FAILED: {exc}"))

        elapsed = time.time() - start
        self.stdout.write(self.style.SUCCESS(
            f"\nDone. {total} submissions processed in {elapsed:.1f}s (avg {elapsed/max(1,total):.2f}s/row)."
        ))
