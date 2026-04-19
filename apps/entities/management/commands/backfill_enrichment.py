"""
Re-run enrichment on entities that were created before a given enricher was
wired in (or when a new enricher gets added later).

    python manage.py backfill_enrichment                  # enrich all entity rows that look unenriched
    python manage.py backfill_enrichment --types ips      # only IPAddress rows
    python manage.py backfill_enrichment --force          # re-enrich even already-populated rows
    python manage.py backfill_enrichment --limit 100      # cap per-type batch size
"""
from __future__ import annotations

from django.core.management.base import BaseCommand

from apps.entities.models import ContactEmail, ContactPhone, IPAddress, SubmitterIP


ALL_TYPES = ("ips", "submitter_ips", "emails", "phones")


class Command(BaseCommand):
    help = "Backfill enrichment on entity rows that missed their initial enrichment pass."

    def add_arguments(self, parser):
        parser.add_argument("--types", default=",".join(ALL_TYPES),
                            help=f"Comma-separated: {', '.join(ALL_TYPES)}")
        parser.add_argument("--force", action="store_true",
                            help="Re-enrich even when fields look populated")
        parser.add_argument("--limit", type=int, default=0,
                            help="Max rows per type (0 = unlimited)")

    def handle(self, *args, types: str, force: bool, limit: int, **options):
        from apps.entities.enrichers import ipqs, maxmind
        from apps.entities.enrichers.email_local import enrich_contact_email
        from apps.entities.enrichers.phone_local import enrich_contact_phone

        type_set = {t.strip() for t in types.split(",") if t.strip()}

        if "ips" in type_set:
            qs = IPAddress.objects.all() if force else IPAddress.objects.filter(country="")
            if limit:
                qs = qs[:limit]
            n = 0
            for ip in qs:
                maxmind.enrich_ip_address(ip)
                ipqs.enrich_ip_address(ip)
                n += 1
            self.stdout.write(self.style.SUCCESS(f"IPAddress: {n} enriched"))

        if "submitter_ips" in type_set:
            qs = SubmitterIP.objects.all() if force else SubmitterIP.objects.filter(country="")
            if limit:
                qs = qs[:limit]
            n = 0
            for sip in qs:
                maxmind.enrich_submitter_ip(sip)
                ipqs.enrich_submitter_ip(sip)
                n += 1
            self.stdout.write(self.style.SUCCESS(f"SubmitterIP: {n} enriched"))

        if "emails" in type_set:
            qs = ContactEmail.objects.all() if force else ContactEmail.objects.filter(mx_reachable__isnull=True)
            if limit:
                qs = qs[:limit]
            n = 0
            for em in qs:
                enrich_contact_email(em)
                n += 1
            self.stdout.write(self.style.SUCCESS(f"ContactEmail: {n} enriched"))

        if "phones" in type_set:
            qs = ContactPhone.objects.all() if force else ContactPhone.objects.filter(line_type="")
            if limit:
                qs = qs[:limit]
            n = 0
            for ph in qs:
                enrich_contact_phone(ph)
                n += 1
            self.stdout.write(self.style.SUCCESS(f"ContactPhone: {n} enriched"))

        self.stdout.write(self.style.SUCCESS("done."))
