"""
Bulk-import submissions from a CSV file.

CSV format: header row required. Supported columns (all optional — at least one
signal per row):

    domain, contact_email, contact_name, contact_phone, submitter_ip,
    device_fingerprint, external_ref

Usage:

    python manage.py import_submissions submissions.csv
    python manage.py import_submissions submissions.csv --org acme
    python manage.py import_submissions submissions.csv --skip-pipeline
    python manage.py import_submissions submissions.csv --dry-run
"""
from __future__ import annotations

import csv

from django.core.management.base import BaseCommand, CommandError

from apps.organizations.models import Organization
from apps.submissions.models import Submission


SIGNAL_COLUMNS = (
    "domain", "contact_email", "contact_name", "contact_phone",
    "submitter_ip", "device_fingerprint",
)


class Command(BaseCommand):
    help = "Bulk-import submissions from a CSV file."

    def add_arguments(self, parser):
        parser.add_argument("path", help="Path to the CSV file (header row required)")
        parser.add_argument("--org", default="acme", help="Organization slug to create submissions under")
        parser.add_argument("--skip-pipeline", action="store_true",
                            help="Create submission rows without running the analyzer pipeline.")
        parser.add_argument("--dry-run", action="store_true",
                            help="Parse and validate the CSV without writing anything.")
        parser.add_argument("--limit", type=int, default=0,
                            help="Stop after N rows (0 = unlimited).")

    def handle(self, *args, path: str, org: str, skip_pipeline: bool, dry_run: bool, limit: int, **options):
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

        rows_created = 0
        rows_skipped = 0

        from apps.api.services import process_submission

        with fh:
            reader = csv.DictReader(fh)
            unknown = set(reader.fieldnames or []) - set(SIGNAL_COLUMNS) - {"external_ref"}
            if unknown:
                self.stdout.write(self.style.WARNING(
                    f"ignored unknown columns: {', '.join(sorted(unknown))}"
                ))

            for i, row in enumerate(reader, start=2):  # row 1 is header
                if limit and rows_created >= limit:
                    break

                values = {k: (row.get(k) or "").strip() for k in SIGNAL_COLUMNS + ("external_ref",)}
                if not any(values[k] for k in SIGNAL_COLUMNS):
                    self.stdout.write(self.style.WARNING(f"row {i}: no signal — skipping"))
                    rows_skipped += 1
                    continue

                if dry_run:
                    self.stdout.write(f"row {i}: {values}")
                    rows_created += 1
                    continue

                sub = Submission.objects.create(
                    organization=organization,
                    api_key=api_key,
                    domain=values["domain"],
                    contact_email_raw=values["contact_email"],
                    contact_name_raw=values["contact_name"],
                    contact_phone_raw=values["contact_phone"],
                    submitter_ip_raw=values["submitter_ip"] or None,
                    device_fingerprint_raw=values["device_fingerprint"],
                    external_ref=values["external_ref"],
                    metadata={"imported_from": path, "source_row": i},
                )

                if skip_pipeline:
                    self.stdout.write(f"row {i}: created {sub.id} (pipeline skipped)")
                else:
                    try:
                        process_submission(sub)
                        sub.refresh_from_db()
                        decision = sub.verdict.decision if hasattr(sub, "verdict") else "—"
                        self.stdout.write(f"row {i}: {sub.domain or values['contact_email']} → {decision}")
                    except Exception as exc:
                        self.stdout.write(self.style.ERROR(f"row {i}: pipeline failed: {exc}"))

                rows_created += 1

        verb = "would create" if dry_run else "created"
        self.stdout.write(self.style.SUCCESS(
            f"\n{verb} {rows_created} submission(s) under org '{organization.slug}'"
            + (f" — {rows_skipped} row(s) skipped" if rows_skipped else "")
        ))
