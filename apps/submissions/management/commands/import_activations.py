"""
Import the Email & Push "App Activations with Send Counts" CSV — each row is one
app → domain → org record. Anything with `last_manual_disable`, `last_auto_disable_at`,
or `sending_disabled=TRUE` is treated as CONFIRMED FRAUD: the submission's verdict
is overridden to DENY, domain-side infrastructure entities (NS / MX / registrar /
resolving IPs) are tagged BAD, and the infrastructure fingerprint's reputation
takes a hit so future matches fail.

CSV format (first line is a spreadsheet title, actual header is line 2):

    app_name, app_created_at, app_disabled, org_name, org_created_at, enterprise,
    org_disabled, domain, domain_activated_at, first_manual_enable,
    last_manual_disable, sending_disabled, last_auto_disable_at,
    email_sends_count, push_sends_count

Usage:
    python manage.py import_activations "path/to/activations.csv"
    python manage.py import_activations file.csv --org acme --dry-run
"""
from __future__ import annotations

import csv
import logging

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.entities.models import IPAddress, MXHost, Nameserver, Registrar, SubmitterIP
from apps.organizations.models import Organization
from apps.submissions.models import Submission, Verdict

logger = logging.getLogger(__name__)


def _truthy(v: str | None) -> bool:
    return bool((v or "").strip()) and (v or "").strip().lower() not in ("false", "0", "no", "")


def _is_disabled(row: dict) -> tuple[bool, str]:
    """Only manual disables count as confirmed fraud per the user's rule."""
    v = (row.get("last_manual_disable") or "").strip()
    if v:
        return True, f"manually disabled on {v}"
    return False, ""


class Command(BaseCommand):
    help = "Import the Email & Push app-activations CSV and tag disabled rows as confirmed fraud."

    def add_arguments(self, parser):
        parser.add_argument("path")
        parser.add_argument("--org", default="acme")
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--skip-pipeline", action="store_true",
                            help="Don't run the analyzer pipeline (just create rows + tag entities).")

    def handle(self, *args, path: str, org: str, dry_run: bool, skip_pipeline: bool, **options):
        try:
            organization = Organization.objects.get(slug=org)
        except Organization.DoesNotExist as exc:
            raise CommandError(f"No organization '{org}'") from exc

        api_key = organization.api_keys.filter(revoked_at__isnull=True).first()

        try:
            fh = open(path, "r", encoding="utf-8-sig", newline="")
        except FileNotFoundError as exc:
            raise CommandError(f"CSV not found: {path}") from exc

        from apps.api.services import process_submission

        created = 0
        tagged = 0
        skipped = 0
        with fh:
            # First line is a spreadsheet title, skip it; header is on line 2.
            first = fh.readline()
            if "," not in first:
                self.stdout.write(f"skipped title line: {first.strip()!r}")
            else:
                fh.seek(0)
            all_rows = list(csv.DictReader(fh))

        # Pass 1: any domain with at least one manual disable anywhere in the CSV
        # infects every row for that same domain (treat the domain itself as fraud).
        fraud_domains: dict[str, str] = {}
        for row in all_rows:
            domain = (row.get("domain") or "").strip().lower()
            if not domain:
                continue
            disabled, reason = _is_disabled(row)
            if disabled and domain not in fraud_domains:
                fraud_domains[domain] = reason
        if fraud_domains:
            self.stdout.write(self.style.WARNING(
                f"confirmed-fraud domains (inherited across all sibling rows): "
                f"{', '.join(sorted(fraud_domains))}"
            ))

        for i, row in enumerate(all_rows, start=3):  # rows start at CSV line 3
            domain = (row.get("domain") or "").strip().lower()
            app = (row.get("app_name") or "").strip()
            org_name = (row.get("org_name") or "").strip()
            if not domain:
                self.stdout.write(self.style.WARNING(f"row {i}: no domain — skipping"))
                skipped += 1
                continue

            row_disabled, row_reason = _is_disabled(row)
            if row_disabled:
                disabled, disable_reason = True, row_reason
            elif domain in fraud_domains:
                disabled, disable_reason = True, (
                    f"sibling row on {domain} is confirmed fraud "
                    f"({fraud_domains[domain]}) — inherited"
                )
            else:
                disabled, disable_reason = False, ""
            external_ref = f"activation:{app} | {org_name}"[:250]

            if dry_run:
                marker = "⛔ DISABLED" if disabled else "  active"
                self.stdout.write(f"row {i}: {marker} {domain} ({app} · {org_name}) — {disable_reason or 'ok'}")
                created += 1
                continue

            sub = Submission.objects.create(
                organization=organization,
                api_key=api_key,
                domain=domain,
                external_ref=external_ref,
                metadata={
                    "imported_from": "activations_csv",
                    "source_row": i,
                    "app_name": app,
                    "org_name": org_name,
                    "domain_activated_at": row.get("domain_activated_at"),
                    "last_manual_disable": row.get("last_manual_disable"),
                    "last_auto_disable_at": row.get("last_auto_disable_at"),
                    "sending_disabled": row.get("sending_disabled"),
                    "email_sends_count": row.get("email_sends_count"),
                    "push_sends_count": row.get("push_sends_count"),
                    "enterprise": row.get("enterprise"),
                    "disabled_confirmed_fraud": disabled,
                    "disable_reason": disable_reason,
                },
            )
            created += 1

            if not skip_pipeline:
                try:
                    process_submission(sub)
                    sub.refresh_from_db()
                except Exception as exc:
                    self.stdout.write(self.style.ERROR(f"row {i}: pipeline failed: {exc}"))

            if disabled:
                n_entities = self._mark_confirmed_fraud(sub, disable_reason)
                tagged += 1
                decision = getattr(getattr(sub, "verdict", None), "decision", "—")
                self.stdout.write(
                    f"row {i}: ⛔ {domain} → override DENY (was {decision}); "
                    f"tagged {n_entities} entities bad"
                )
            else:
                decision = getattr(getattr(sub, "verdict", None), "decision", "—")
                self.stdout.write(f"row {i}: {domain} → {decision}")

        verb = "would create" if dry_run else "created"
        self.stdout.write(self.style.SUCCESS(
            f"{verb} {created} submissions — {tagged} tagged as confirmed fraud — {skipped} skipped."
        ))

    # ------------------------------------------------------------------
    def _mark_confirmed_fraud(self, sub: Submission, reason: str) -> int:
        """
        Override verdict to DENY + tag all domain-side infrastructure entities bad.
        Bumps the infrastructure fingerprint reputation via the same path as the
        console's cluster-mark button.
        """
        from apps.fingerprints.models import Fingerprint, FingerprintReputation
        from apps.fingerprints.services import _recompute_score

        who = "import:activations"
        now = timezone.now()
        tag_reason = f"Confirmed fraud — {reason}"
        updates = {"tag": "bad", "tag_reason": tag_reason, "tagged_at": now, "tagged_by": who}

        # --- verdict override -----------------------------------------
        verdict = getattr(sub, "verdict", None)
        if verdict is None:
            # No pipeline run or it failed — create a minimal overridden verdict so
            # the submission still surfaces as DENY in the UI.
            verdict = Verdict.objects.create(
                submission=sub,
                decision=Verdict.DECISION_DENY,
                score=100,
                summary=f"⛔ CONFIRMED FRAUD — {reason}",
                reasons=[{"code": "manual_disable", "weight": 100, "detail": reason}],
                raw={},
            )
            verdict.review_status = Verdict.REVIEW_CONFIRMED
            verdict.human_override_decision = Verdict.DECISION_DENY
        else:
            # If system already said deny, mark CONFIRMED; otherwise CORRECTED.
            if verdict.decision == Verdict.DECISION_DENY:
                verdict.review_status = Verdict.REVIEW_CONFIRMED
                verdict.human_override_decision = ""  # agreement — no override needed
            else:
                verdict.review_status = Verdict.REVIEW_CORRECTED
                verdict.human_override_decision = Verdict.DECISION_DENY
        verdict.human_override_reason = tag_reason
        verdict.human_override_by = who
        verdict.human_override_at = now
        verdict.save()

        # --- bulk-tag domain-side entities ----------------------------
        n = 0
        ds = getattr(sub, "domain_scan", None)
        if ds is not None:
            # Nameservers
            for link in ds.nameserver_links.select_related("nameserver").all():
                Nameserver.objects.filter(pk=link.nameserver_id).update(**updates)
                n += 1
            # MX hosts
            for link in ds.mx_links.select_related("mx_host").all():
                MXHost.objects.filter(pk=link.mx_host_id).update(**updates)
                n += 1
            # Registrar
            if ds.registrar_id:
                Registrar.objects.filter(pk=ds.registrar_id).update(**updates)
                n += 1
            # Resolving IPs — skip any VPN/proxy/Tor (shared infra)
            for link in ds.ip_links.select_related("ip_address").all():
                ip = link.ip_address
                if ip.is_vpn or ip.is_proxy or ip.is_tor:
                    continue
                IPAddress.objects.filter(pk=ip.pk).update(**updates)
                SubmitterIP.objects.filter(address=ip.address).update(**updates)
                n += 1

        # --- bump infrastructure fingerprint reputation ---------------
        infra_fp = Fingerprint.objects.filter(
            submission_links__submission=sub,
            submission_links__is_primary=True,
            kind=Fingerprint.KIND_INFRASTRUCTURE,
        ).first()
        if infra_fp:
            rep, _ = FingerprintReputation.objects.get_or_create(fingerprint=infra_fp)
            rep.flagged_count += 1
            rep.feedback_false_negative_count += 1
            rep.cluster_verdict = "bad"
            rep.cluster_verdict_at = now
            rep.cluster_verdict_by = who
            rep.cluster_verdict_reason = tag_reason
            rep.cluster_verdict_size = max(rep.cluster_verdict_size, 1)
            rep.reputation_score = _recompute_score(rep)
            rep.save()

        return n
