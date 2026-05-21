"""
Import from eHawk's DETAILED "Domain Review" CSV export — the ~400-column
format with every risk signal as its own column.

eHawk's detailed export uses POSITION-based column semantics with the same
header name appearing twice meaning different things:

    col 5  domain          = actual domain name (identity)
    col 7  ip              = score (numeric, e.g. -20)
    col 8  email           = score (numeric — no raw email value in this export)
    col 9  domain          = score (numeric — domain's per-dimension score)
    col 10 name            = score
    col 11 phone           = score
    col 12 location        = score
    col 13 geolocation     = score
    col 14 activity        = score
    col 15 fingerprint     = score
    col 16 community       = score
    col 17 ssn             = score
    col 18 combo           = score
    col 19 custom_fields   = score
    col 30 fingerprint     = actual device fingerprint hash (identity)
    col 31 fingerprint_ua  = user agent
    col 32 ip              = actual IP address (identity)
    col 33 ip_location     = geo summary string
    col 34+                = per-signal flag columns (Blacklist, Proxy, Disposable, ...)

We extract identity fields from their known positions, store per-dimension
scores + lead metadata under metadata.ehawk_*, and capture every non-empty
signal flag in metadata.ehawk_flags. The email/name/phone raw VALUES are
absent from this CSV format — only their scores are present.

Usage:
    python manage.py import_ehawk_detailed "path/to/Domain Review.csv"
    python manage.py import_ehawk_detailed "path/to/Domain Review.csv" --dry-run
"""
from __future__ import annotations

import csv
import ipaddress

from django.core.management.base import BaseCommand, CommandError

from apps.organizations.models import Organization
from apps.submissions.models import Submission


# Identity fields at fixed column indices.
IDENTITY_POSITIONS = {
    "domain":                  5,
    "device_fingerprint_raw":  30,
    "submitter_ip_raw":        32,
}

# Per-dimension scores at fixed column indices → metadata keys.
SCORE_POSITIONS = {
    7:  "ehawk_ip_score",
    8:  "ehawk_email_score",
    9:  "ehawk_domain_score",
    10: "ehawk_name_score",
    11: "ehawk_phone_score",
    12: "ehawk_location_score",
    13: "ehawk_geolocation_score",
    14: "ehawk_activity_score",
    15: "ehawk_fingerprint_score",
    16: "ehawk_community_score",
    17: "ehawk_ssn_score",
    18: "ehawk_combo_score",
    19: "ehawk_custom_fields_score",
}

# Lead metadata at fixed positions → metadata keys.
META_POSITIONS = {
    0:  "ehawk_id",
    1:  "ehawk_username",
    2:  "ehawk_lead_id",
    3:  "ehawk_score_total",
    4:  "ehawk_score",
    6:  "ehawk_risk_type",
    20: "ehawk_transaction_id",
    21: "ehawk_timestamp",
    22: "ehawk_street",
    23: "ehawk_city",
    24: "ehawk_state",
    25: "ehawk_postalcode",
    26: "ehawk_country",
    27: "ehawk_lead_source",
    28: "ehawk_sub_id",
    29: "ehawk_campaign_id",
    31: "ehawk_fingerprint_ua",
    33: "ehawk_ip_location",
}

# Signal flags begin at this column.
FLAG_START = 34


def _safe_ip(value: str) -> str | None:
    """Return the IP if it parses as v4/v6, else None."""
    if not value:
        return None
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        return None


class Command(BaseCommand):
    help = "Import from eHawk's detailed Domain Review CSV (~400 columns)."

    def add_arguments(self, parser):
        parser.add_argument("path")
        parser.add_argument("--org", default="acme")
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--limit", type=int, default=0)

    def handle(self, *args, path: str, org: str, dry_run: bool, limit: int, **options):
        try:
            organization = Organization.objects.get(slug=org)
        except Organization.DoesNotExist as exc:
            raise CommandError(f"No organization with slug '{org}'") from exc

        api_key = organization.api_keys.filter(revoked_at__isnull=True).first()

        try:
            fh = open(path, "r", encoding="utf-8-sig", newline="")
        except FileNotFoundError as exc:
            raise CommandError(f"CSV file not found: {path}") from exc

        with fh:
            reader = csv.reader(fh)
            headers = next(reader)
            self.stdout.write(f"columns: {len(headers)}  (identity at cols {list(IDENTITY_POSITIONS.values())}, flags start at col {FLAG_START})")

            created = 0
            skipped = 0

            for row_num, row in enumerate(reader, start=2):
                if limit and created >= limit:
                    break

                def cell(idx: int) -> str:
                    return (row[idx] or "").strip() if idx < len(row) else ""

                # Identity fields
                domain = cell(IDENTITY_POSITIONS["domain"])
                device_fp = cell(IDENTITY_POSITIONS["device_fingerprint_raw"])
                raw_ip = cell(IDENTITY_POSITIONS["submitter_ip_raw"])
                submitter_ip = _safe_ip(raw_ip)  # None if not a valid IP string

                if not any([domain, device_fp, submitter_ip]):
                    skipped += 1
                    continue

                # Metadata: dimension scores + lead metadata + signal flags
                metadata: dict = {"imported_from": "ehawk_domain_review", "source_row": row_num}

                for idx, key in SCORE_POSITIONS.items():
                    val = cell(idx)
                    if val:
                        metadata[key] = val

                for idx, key in META_POSITIONS.items():
                    val = cell(idx)
                    if val:
                        metadata[key] = val

                if submitter_ip is None and raw_ip:
                    metadata["ehawk_raw_ip_unparseable"] = raw_ip

                # Signal flags: every non-empty col >= FLAG_START
                flags: dict[str, str] = {}
                for i in range(FLAG_START, min(len(row), len(headers))):
                    val = (row[i] or "").strip()
                    if val:
                        flags[headers[i]] = val
                if flags:
                    metadata["ehawk_flags"] = flags
                    metadata["ehawk_flags_set_count"] = len(flags)

                external_ref = metadata.get("ehawk_lead_source") or metadata.get("ehawk_lead_id") or metadata.get("ehawk_id") or ""

                if dry_run:
                    self.stdout.write(
                        f"row {row_num}: domain={domain or '—':30} ip={submitter_ip or '—':16} "
                        f"fp={device_fp[:8] or '—':8}  score={metadata.get('ehawk_score', '?')}  "
                        f"flags={len(flags)}"
                    )
                    created += 1
                    continue

                Submission.objects.create(
                    organization=organization,
                    api_key=api_key,
                    domain=domain,
                    contact_email_raw="",  # not present in this CSV format
                    contact_name_raw="",
                    contact_phone_raw="",
                    submitter_ip_raw=submitter_ip,
                    device_fingerprint_raw=device_fp,
                    external_ref=external_ref,
                    metadata=metadata,
                )
                created += 1
                self.stdout.write(
                    f"row {row_num}: {domain or submitter_ip or device_fp[:12]} "
                    f"(score={metadata.get('ehawk_score', '?')}, {len(flags)} flags)"
                )

        verb = "would create" if dry_run else "created"
        self.stdout.write(self.style.SUCCESS(
            f"\n{verb} {created} submission(s)"
            + (f" — {skipped} skipped" if skipped else "")
        ))
