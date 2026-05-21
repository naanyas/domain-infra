"""
Delete submissions matching one or more filters. Intended for cleaning up
test / example data after development runs.

    # Delete submissions for known test domains
    python manage.py purge_submissions --domains example.com,iana.org

    # Delete by external_ref pattern
    python manage.py purge_submissions --external-refs ipqs-smoke-1,maxmind-smoke-1,email-phone-test-1

    # Dry-run (show what would be deleted; no writes)
    python manage.py purge_submissions --domains example.com --dry-run

    # Aggressive: purge everything NOT from a bulk import
    python manage.py purge_submissions --no-imported-from
"""
from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError
from django.db.models import Q

from apps.organizations.models import Organization
from apps.submissions.models import Submission


class Command(BaseCommand):
    help = "Delete submissions matching filter(s). Multiple filters are OR'd."

    def add_arguments(self, parser):
        parser.add_argument("--org", default="acme", help="Organization slug to scope the purge to")
        parser.add_argument("--domains", default="",
                            help="Comma-separated domains to match (exact)")
        parser.add_argument("--external-refs", default="",
                            help="Comma-separated external_ref values to match (exact)")
        parser.add_argument("--no-imported-from", action="store_true",
                            help="Delete rows without metadata.imported_from (i.e., non-bulk-import)")
        parser.add_argument("--dry-run", action="store_true",
                            help="Show what would be deleted without writing.")

    def handle(self, *args, org: str, domains: str, external_refs: str,
               no_imported_from: bool, dry_run: bool, **options):
        try:
            organization = Organization.objects.get(slug=org)
        except Organization.DoesNotExist as exc:
            raise CommandError(f"No organization with slug '{org}'") from exc

        filters = Q()
        applied: list[str] = []

        if domains:
            domain_list = [d.strip() for d in domains.split(",") if d.strip()]
            filters |= Q(domain__in=domain_list)
            applied.append(f"domains={domain_list}")

        if external_refs:
            ref_list = [r.strip() for r in external_refs.split(",") if r.strip()]
            filters |= Q(external_ref__in=ref_list)
            applied.append(f"external_refs={ref_list}")

        if no_imported_from:
            filters |= ~Q(metadata__has_key="imported_from")
            applied.append("no imported_from metadata")

        if not applied:
            raise CommandError("No filter supplied. Use --domains, --external-refs, or --no-imported-from.")

        target = Submission.objects.filter(organization=organization).filter(filters)
        count = target.count()

        self.stdout.write(f"Filters OR'd: {'; '.join(applied)}")
        self.stdout.write(f"Matched {count} submission(s).\n")

        for s in target.order_by("created_at")[:20]:
            ref = s.external_ref or "—"
            self.stdout.write(
                f"  {s.created_at:%m-%d %H:%M}  "
                f"{s.domain or '—':30}  "
                f"{s.contact_email_raw or '—':40}  "
                f"ref={ref}"
            )
        if count > 20:
            self.stdout.write(f"  ... and {count - 20} more")

        if dry_run:
            self.stdout.write(self.style.NOTICE(f"\nDRY RUN — no rows deleted."))
            return

        if count == 0:
            self.stdout.write(self.style.NOTICE("Nothing to delete."))
            return

        deleted, _ = target.delete()
        self.stdout.write(self.style.SUCCESS(f"\nDeleted {deleted} row(s) (includes cascading domain_scans, verdicts, fingerprint links)."))
