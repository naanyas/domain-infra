"""
Import submissions from an eHawk "vet search" CSV export.

eHawk's CSV schema maps cleanly onto domain-infra's signal model:

    ip                   → submitter_ip_raw
    email                → contact_email_raw
    domain               → domain
    phone                → contact_phone_raw  (often empty)
    name                 → contact_name_raw
    fingerprint          → device_fingerprint_raw  (eHawk's device hash)
    fingerprint_os       → metadata.ehawk_fingerprint_os
    lead_source          → external_ref
    App Name (Custom1)   → metadata.ehawk_app
    Org Name (Custom3)   → metadata.ehawk_org
    total_score          → metadata.ehawk_score  (eHawk's verdict — -100..+100)
    timestamp            → metadata.ehawk_timestamp
    geo_ip               → metadata.ehawk_geo (we also derive geo from MaxMind)

Usage:

    python manage.py import_ehawk "path/to/ehawk.csv"                # run full pipeline on every row (slow — ~20s each)
    python manage.py import_ehawk "path/to/ehawk.csv" --limit 15     # full pipeline on first 15 only
    python manage.py import_ehawk "path/to/ehawk.csv" --skip-pipeline  # just create the rows (fast)
    python manage.py import_ehawk "path/to/ehawk.csv" --dry-run      # parse + validate, no writes
"""
from __future__ import annotations

import csv

from django.core.management.base import BaseCommand, CommandError

from apps.organizations.models import Organization
from apps.submissions.models import Submission


COLUMN_MAP = {
    "ip":          "submitter_ip_raw",
    "email":       "contact_email_raw",
    "domain":      "domain",
    "phone":       "contact_phone_raw",
    "name":        "contact_name_raw",
    "fingerprint": "device_fingerprint_raw",
}

METADATA_COLUMNS = {
    "geo_ip":             "ehawk_geo",
    "fingerprint_os":     "ehawk_fingerprint_os",
    "App Name (Custom1)": "ehawk_app",
    "Org Name (Custom3)": "ehawk_org",
    "total_score":        "ehawk_score",
    "timestamp":          "ehawk_timestamp",
}


class Command(BaseCommand):
    help = "Import submissions from an eHawk vet-search CSV export."

    def add_arguments(self, parser):
        parser.add_argument("path", help="Path to the eHawk CSV file")
        parser.add_argument("--org", default="acme", help="Organization slug to scope submissions to")
        parser.add_argument("--limit", type=int, default=0, help="Stop after N rows (0 = all)")
        parser.add_argument("--offset", type=int, default=0, help="Skip the first N data rows")
        parser.add_argument("--skip-pipeline", action="store_true",
                            help="Create rows without running analyzer + enrichers (fast).")
        parser.add_argument("--dry-run", action="store_true",
                            help="Parse and validate the CSV without writing anything.")

    def handle(self, *args, path: str, org: str, limit: int, offset: int,
               skip_pipeline: bool, dry_run: bool, **options):
        try:
            organization = Organization.objects.get(slug=org)
        except Organization.DoesNotExist as exc:
            raise CommandError(
                f"No organization with slug '{org}'. Run: python manage.py bootstrap --slug {org}"
            ) from exc

        api_key = organization.api_keys.filter(revoked_at__isnull=True).first()

        try:
            fh = open(path, "r", encoding="utf-8-sig", newline="")
        except FileNotFoundError as exc:
            raise CommandError(f"CSV file not found: {path}") from exc

        from apps.api.services import process_submission

        rows_created = 0
        rows_skipped = 0
        rows_seen = 0

        with fh:
            reader = csv.DictReader(fh)

            for i, row in enumerate(reader, start=2):  # row 1 is header
                rows_seen += 1
                if rows_seen <= offset:
                    continue
                if limit and rows_created >= limit:
                    break

                # Map signal columns
                fields: dict = {}
                for src, dest in COLUMN_MAP.items():
                    fields[dest] = (row.get(src) or "").strip()

                # Submitter IP cleanup — model is GenericIPAddressField, empty → None.
                if not fields["submitter_ip_raw"]:
                    fields["submitter_ip_raw"] = None

                if not any([
                    fields.get("domain"), fields.get("contact_email_raw"),
                    fields.get("contact_name_raw"), fields.get("contact_phone_raw"),
                    fields.get("submitter_ip_raw"), fields.get("device_fingerprint_raw"),
                ]):
                    self.stdout.write(self.style.WARNING(f"row {i}: no signal — skipping"))
                    rows_skipped += 1
                    continue

                metadata = {"imported_from": "ehawk_vet_search", "source_row": i}
                for src, dest in METADATA_COLUMNS.items():
                    val = (row.get(src) or "").strip()
                    if val:
                        metadata[dest] = val

                external_ref = (row.get("lead_source") or "").strip()

                if dry_run:
                    self.stdout.write(f"row {i}: {fields.get('domain') or fields.get('contact_email_raw')} "
                                      f"@ {fields.get('submitter_ip_raw') or '—'} "
                                      f"[ehawk_score={metadata.get('ehawk_score', '?')}]")
                    rows_created += 1
                    continue

                sub = Submission.objects.create(
                    organization=organization,
                    api_key=api_key,
                    domain=fields["domain"],
                    contact_email_raw=fields["contact_email_raw"],
                    contact_name_raw=fields["contact_name_raw"],
                    contact_phone_raw=fields["contact_phone_raw"],
                    submitter_ip_raw=fields["submitter_ip_raw"],
                    device_fingerprint_raw=fields["device_fingerprint_raw"],
                    external_ref=external_ref,
                    metadata=metadata,
                )

                if skip_pipeline:
                    self.stdout.write(f"row {i}: {sub.domain or fields['contact_email_raw']} "
                                      f"→ created (pipeline skipped)")
                else:
                    try:
                        process_submission(sub)
                        sub.refresh_from_db()
                        decision = sub.verdict.decision if hasattr(sub, "verdict") else "—"
                        self.stdout.write(
                            f"row {i}: {sub.domain or fields['contact_email_raw']} → {decision}"
                        )
                    except Exception as exc:
                        self.stdout.write(self.style.ERROR(f"row {i}: pipeline failed: {exc}"))

                rows_created += 1

        verb = "would create" if dry_run else "created"
        note = " + pipeline ran" if (not skip_pipeline and not dry_run) else ""
        self.stdout.write(self.style.SUCCESS(
            f"\n{verb} {rows_created} submission(s){note} under org '{organization.slug}'"
            + (f" — {rows_skipped} row(s) skipped" if rows_skipped else "")
        ))
