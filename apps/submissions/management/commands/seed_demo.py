"""
Seed a curated set of varied submissions for demo purposes.

Runs the full pipeline (analyzer + enrichers + fingerprinting + rules),
so expect ~15-25 seconds per submission. Good for populating a dashboard
before a colleague demo.

    python manage.py seed_demo
    python manage.py seed_demo --org acme
    python manage.py seed_demo --skip-pipeline     # just create the rows, no analyzer
"""
from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from apps.organizations.models import Organization
from apps.submissions.models import Submission


# Each scenario highlights a different product angle.
SCENARIOS: list[dict] = [
    {
        "label": "Clean established domain + consumer email",
        "domain": "github.com",
        "contact_email": "taylor@gmail.com",
        "contact_name": "Taylor Morgan",
        "contact_phone": "+14155551234",
        "submitter_ip": "73.109.21.44",          # Comcast residential-ish
        "external_ref": "demo-1-clean",
    },
    {
        "label": "Clean domain + DISPOSABLE email + role handle",
        "domain": "stripe.com",
        "contact_email": "admin@mailinator.com",
        "contact_name": "Jane Doe",
        "contact_phone": "+14155550000",
        "submitter_ip": "73.109.21.44",
        "external_ref": "demo-2-disposable-email",
    },
    {
        "label": "Clean domain + VPN submitter IP (Hetzner)",
        "domain": "cloudflare.com",
        "contact_email": "user@protonmail.com",
        "contact_name": "Bob Smith",
        "contact_phone": "+442079460958",         # UK fixed-line
        "submitter_ip": "5.9.33.17",              # AS24940 Hetzner, IPQS flags as VPN
        "external_ref": "demo-3-vpn-ip",
    },
    {
        "label": "Large legacy domain + role email + EU submitter",
        "domain": "wikipedia.org",
        "contact_email": "support@wikimedia.org",
        "contact_name": "Alice Keeper",
        "contact_phone": "+33142682468",          # France
        "submitter_ip": "213.186.33.5",           # OVH France
        "external_ref": "demo-4-role-email",
    },
    {
        "label": "Repeat of demo-1 (fingerprint exact-match demo)",
        "domain": "github.com",
        "contact_email": "taylor@gmail.com",
        "contact_name": "Taylor Morgan",
        "contact_phone": "+14155551234",
        "submitter_ip": "73.109.21.44",
        "external_ref": "demo-5-fingerprint-repeat",
    },
    {
        "label": "Minimal signal (email only)",
        "contact_email": "test@icloud.com",
        "contact_name": "Pat Lee",
        "external_ref": "demo-6-email-only",
    },
    {
        "label": "High-auth domain + free email + US",
        "domain": "example.com",
        "contact_email": "founder@hey.com",
        "contact_name": "Jordan Reyes",
        "submitter_ip": "8.8.8.8",                # Google DNS (datacenter, not residential)
        "external_ref": "demo-7-datacenter-submitter",
    },
]


class Command(BaseCommand):
    help = "Seed a curated set of demo submissions for populating the dashboard."

    def add_arguments(self, parser):
        parser.add_argument("--org", default="acme", help="Organization slug to create submissions under")
        parser.add_argument("--skip-pipeline", action="store_true",
                            help="Create submission rows without running the analyzer pipeline (fast).")

    def handle(self, *args, org: str, skip_pipeline: bool, **options):
        try:
            organization = Organization.objects.get(slug=org)
        except Organization.DoesNotExist as exc:
            raise CommandError(
                f"No organization with slug '{org}'. Run: python manage.py bootstrap --slug {org}"
            ) from exc

        api_key = organization.api_keys.filter(revoked_at__isnull=True).first()

        from apps.api.services import process_submission

        for i, scn in enumerate(SCENARIOS, start=1):
            self.stdout.write(f"[{i}/{len(SCENARIOS)}] {scn['label']} ...")
            sub = Submission.objects.create(
                organization=organization,
                api_key=api_key,
                domain=scn.get("domain", ""),
                contact_email_raw=scn.get("contact_email", ""),
                contact_name_raw=scn.get("contact_name", ""),
                contact_phone_raw=scn.get("contact_phone", ""),
                submitter_ip_raw=scn.get("submitter_ip") or None,
                device_fingerprint_raw=scn.get("device_fingerprint", ""),
                external_ref=scn.get("external_ref", ""),
                metadata={"seed_demo": True, "scenario": scn["label"]},
            )
            if not skip_pipeline:
                try:
                    process_submission(sub)
                    sub.refresh_from_db()
                    decision = sub.verdict.decision if hasattr(sub, "verdict") else "—"
                    self.stdout.write(self.style.SUCCESS(f"    → {decision} (status {sub.status})"))
                except Exception as exc:
                    self.stdout.write(self.style.ERROR(f"    → pipeline failed: {exc}"))
            else:
                self.stdout.write(self.style.NOTICE(f"    → created (pipeline skipped)"))

        self.stdout.write(self.style.SUCCESS(f"\nSeeded {len(SCENARIOS)} submissions under org '{organization.slug}'."))
