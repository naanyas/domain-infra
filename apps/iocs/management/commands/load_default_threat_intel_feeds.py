"""Seed the default set of external threat-intel feeds. Idempotent."""
from django.core.management.base import BaseCommand
from apps.iocs.fetchers import DEFAULT_FEEDS
from apps.iocs.models import ThreatIntelFeed


class Command(BaseCommand):
    help = "Seed ThreatIntelFeed with the default external feed roster."

    def handle(self, *args, **options):
        created = updated = 0
        for cfg in DEFAULT_FEEDS:
            obj, was_created = ThreatIntelFeed.objects.update_or_create(
                name=cfg["name"],
                defaults={k: v for k, v in cfg.items() if k != "name"},
            )
            if was_created:
                created += 1
            else:
                updated += 1
        self.stdout.write(self.style.SUCCESS(
            f"Feeds: {created} created, {updated} updated. Total now: {ThreatIntelFeed.objects.count()}."
        ))
