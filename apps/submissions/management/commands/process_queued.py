"""
Run the analyzer/enricher/fingerprint pipeline on queued submissions.

Each submission with a domain takes ~15-25 seconds (analyzer does real DNS,
WHOIS, HTTP, TLS, CT-log lookups). Submissions without a domain are much faster.
Use --limit for batches; all 1000+ rows at once would be hours.

    python manage.py process_queued --limit 10                 # next 10 queued
    python manage.py process_queued --limit 50 --skip-domain   # skip slow domain rows
    python manage.py process_queued --ids uuid1,uuid2          # specific rows
    python manage.py process_queued --limit 0                  # all (be careful)
"""
from __future__ import annotations

import time

from django.core.management.base import BaseCommand, CommandError

from apps.organizations.models import Organization
from apps.submissions.models import Submission


class Command(BaseCommand):
    help = "Run the analyzer pipeline on queued submissions."

    def add_arguments(self, parser):
        parser.add_argument("--org", default="acme")
        parser.add_argument("--limit", type=int, default=20,
                            help="Max rows to process (default 20; use 0 for unlimited).")
        parser.add_argument("--ids", default="",
                            help="Comma-separated submission UUIDs to process (overrides filters).")
        parser.add_argument("--skip-domain", action="store_true",
                            help="Only process submissions that have NO domain (fast — skips analyzer).")
        parser.add_argument("--domain-only", action="store_true",
                            help="Only process submissions that HAVE a domain (slow — runs analyzer).")

    def handle(self, *args, org: str, limit: int, ids: str, skip_domain: bool, domain_only: bool, **options):
        try:
            organization = Organization.objects.get(slug=org)
        except Organization.DoesNotExist as exc:
            raise CommandError(f"No organization with slug '{org}'") from exc

        if skip_domain and domain_only:
            raise CommandError("--skip-domain and --domain-only are mutually exclusive")

        qs = Submission.objects.filter(
            organization=organization,
            status=Submission.STATUS_QUEUED,
        )
        if ids:
            id_list = [s.strip() for s in ids.split(",") if s.strip()]
            qs = qs.filter(id__in=id_list)
        elif skip_domain:
            qs = qs.filter(domain="")
        elif domain_only:
            qs = qs.exclude(domain="")

        qs = qs.order_by("created_at")
        if limit > 0:
            qs = qs[:limit]

        total = qs.count()
        if total == 0:
            self.stdout.write("Nothing queued matching those filters.")
            return

        self.stdout.write(f"Processing {total} queued submission(s)...\n")

        from apps.api.services import process_submission

        start = time.time()
        for i, sub in enumerate(qs, start=1):
            ident = sub.domain or sub.contact_email_raw or sub.submitter_ip_raw or f"fp:{(sub.device_fingerprint_raw or '')[:8]}" or "—"
            self.stdout.write(f"[{i:>4}/{total}] {ident:45} ", ending="")
            try:
                t0 = time.time()
                process_submission(sub)
                dt = time.time() - t0
                sub.refresh_from_db()
                decision = sub.verdict.decision if hasattr(sub, "verdict") else "—"
                score = sub.verdict.score if hasattr(sub, "verdict") else 0
                self.stdout.write(self.style.SUCCESS(f"→ {decision:7} score={score:>4}  ({dt:.1f}s)"))
            except Exception as exc:
                self.stdout.write(self.style.ERROR(f"→ FAILED: {exc}"))

        elapsed = time.time() - start
        remaining = Submission.objects.filter(
            organization=organization, status=Submission.STATUS_QUEUED,
        ).count()
        self.stdout.write(self.style.SUCCESS(
            f"\nDone. {total} processed in {elapsed:.1f}s. "
            f"{remaining} submission(s) still queued."
        ))
